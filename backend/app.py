from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
import mysql.connector
import bcrypt
import re
import secrets
import os
import json
import smtplib
import ssl
import time
from pathlib import Path
from email.message import EmailMessage
from threading import Lock
from contextlib import contextmanager
from urllib.parse import urlencode
from dotenv import load_dotenv
from datetime import datetime, timedelta
from functools import wraps

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
app = Flask(__name__)
# Persistir la clave local evita cerrar las sesiones con cada reinicio.
key_path = BASE_DIR / ".session-key"
if not os.getenv("SECRET_KEY") and not key_path.exists():
    try:
        with key_path.open("x", encoding="utf-8") as key_file:
            key_file.write(secrets.token_hex(32))
    except FileExistsError:
        pass
app.secret_key = os.getenv("SECRET_KEY") or key_path.read_text(encoding="utf-8").strip()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() == "true",
                  PERMANENT_SESSION_LIFETIME=timedelta(hours=8), MAX_CONTENT_LENGTH=16384)
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000/frontend").rstrip("/")
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5500,http://127.0.0.1:5500,http://127.0.0.1:3000").split(",") if o.strip()]
CORS(app, supports_credentials=True, origins=ALLOWED_ORIGINS, allow_headers=["Content-Type"])


@app.before_request
def comprobar_origen():
    # Los formularios y fetch de otros sitios no pueden modificar una sesión.
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("Origin")
        if origin and origin not in ALLOWED_ORIGINS:
            return jsonify(success=False, message="Origen no permitido"), 403
        if not request.is_json:
            return jsonify(success=False, message="Se requiere JSON"), 415


@app.route("/frontend/<path:filename>")
def frontend(filename):
    return send_from_directory(BASE_DIR.parent / "frontend", filename)

def conectar_bd():
    return mysql.connector.connect(host=os.getenv("DB_HOST", "localhost"), user=os.getenv("DB_USER", "root"),
                                   password=os.getenv("DB_PASSWORD", ""), database=os.getenv("DB_NAME", "rappiya"),
                                   port=int(os.getenv("DB_PORT", "3306")))


@contextmanager
def transaccion():
    conn = conectar_bd()
    cur = None
    try:
        conn.start_transaction()
        cur = conn.cursor(dictionary=True)
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        if cur is not None:
            cur.close()
        conn.close()

def db_query(sql, params=(), one=False):
    with transaccion() as cur:
        cur.execute(sql, params)
        return cur.fetchone() if one else cur.fetchall()

def db_exec(sql, params=()):
    with transaccion() as cur:
        cur.execute(sql, params)
        return cur.lastrowid


def registrar_auditoria(cur, accion, entidad, entidad_id, anterior, nuevo):
    cur.execute("""INSERT INTO auditoria (actor_id, accion, entidad, entidad_id, valor_anterior, valor_nuevo)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (request.usuario_actual["id"], accion, entidad, entidad_id,
                 json.dumps(anterior, ensure_ascii=False, default=str),
                 json.dumps(nuevo, ensure_ascii=False, default=str)))


def enviar_recuperacion(email, token):
    host = os.getenv("SMTP_HOST")
    sender = os.getenv("SMTP_FROM")
    if not host or not sender:
        raise RuntimeError("Configurar SMTP_HOST y SMTP_FROM en backend/.env")
    message = EmailMessage()
    message["Subject"] = "RappiYa - Recuperar contraseña"
    message["From"] = sender
    message["To"] = email
    link = FRONTEND_URL + "/restablecerpass.html?" + urlencode({"token": token})
    message.set_content(f"Abrí este enlace para cambiar tu contraseña:\n\n{link}\n\n"
                        "El enlace vence en 15 minutos y se puede utilizar una sola vez.\n"
                        "Si no lo solicitaste, ignorá este correo.")
    secure = os.getenv("SMTP_SECURITY", "starttls").lower()
    if secure not in ("ssl", "starttls", "none"):
        raise RuntimeError("SMTP_SECURITY debe ser ssl, starttls o none")
    port = int(os.getenv("SMTP_PORT", "465" if secure == "ssl" else "587"))
    factory = smtplib.SMTP_SSL if secure == "ssl" else smtplib.SMTP
    kwargs = {"timeout": 15}
    if secure == "ssl":
        kwargs["context"] = ssl.create_default_context()
    with factory(host, port, **kwargs) as smtp:
        if secure == "starttls":
            smtp.starttls(context=ssl.create_default_context())
        if os.getenv("SMTP_USER"):
            smtp.login(os.environ["SMTP_USER"], os.getenv("SMTP_PASSWORD", ""))
        smtp.send_message(message)


# Límite local por IP, acotado y sincronizado para el servidor de práctica.
intentos_login = {}
intentos_lock = Lock()
LOGIN_WINDOW = 15 * 60
LOGIN_MAX = 5


def reservar_intento(ip):
    ahora = time.monotonic()
    with intentos_lock:
        for key in list(intentos_login):
            if ahora - intentos_login[key][0] >= LOGIN_WINDOW:
                del intentos_login[key]
        if ip not in intentos_login:
            if len(intentos_login) >= 10000:
                return False
            intentos_login[ip] = [ahora, 0]
        entry = intentos_login[ip]
        if entry[1] >= LOGIN_MAX:
            return False
        entry[1] += 1
        return True

def email_valido(email):
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email) is not None

def password_segura(password):
    return len(password) >= 8 and bool(re.search(r"[A-Z]", password)) and bool(re.search(r"[0-9]", password))

def validar_telefono(telefono):
    return bool(re.fullmatch(r"\+?[0-9 ()-]+", telefono)) and 8 <= len(re.sub(r"\D", "", telefono)) <= 15

def hashear_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def obtener_usuario_actual():
    uid = session.get("usuario_id")
    if not uid:
        return None
    try:
        sql = """
            SELECT u.id, u.nombre, u.email, u.estado, u.rol_id, u.direccion, u.telefono,
                   r.codigo AS rol_codigo, r.nombre AS rol_nombre
            FROM usuarios u LEFT JOIN roles r ON u.rol_id = r.id WHERE u.id = %s AND r.activo = 1
        """
        u = db_query(sql, (uid,), one=True)
        return u if (u and u["estado"] == 1) else None
    except Exception:
        return None

def login_requerido(f):
    @wraps(f)
    def decorada(*args, **kwargs):
        u = obtener_usuario_actual()
        if not u:
            return jsonify({"success": False, "message": "Sesión no iniciada o inválida. Por favor iniciá sesión."}), 401
        request.usuario_actual = u
        return f(*args, **kwargs)
    return decorada

def requiere_rol(*roles_permitidos):
    def decorador(f):
        @wraps(f)
        def decorada(*args, **kwargs):
            u = obtener_usuario_actual()
            if not u:
                return jsonify({"success": False, "message": "Sesión requerida"}), 401
            if u.get("rol_codigo") not in roles_permitidos:
                return jsonify({"success": False, "message": "Acceso denegado: no tenés permisos para realizar esta acción"}), 403
            request.usuario_actual = u
            return f(*args, **kwargs)
        return decorada
    return decorador

@app.route("/", methods=["GET"])
def inicio():
    return jsonify({"mensaje": "Backend de RappiYa funcionando correctamente"})

@app.route("/registro", methods=["POST"])
def registro():
    try:
        datos = request.get_json() or {}
        nombre = datos.get("name", "").strip()
        email = datos.get("email", "").strip()
        password = datos.get("password", "")

        if not nombre or not email or not password:
            return jsonify({"success": False, "message": "Todos los campos son obligatorios"}), 400
        if not email_valido(email):
            return jsonify({"success": False, "message": "El formato del correo electrónico es inválido"}), 400
        if not password_segura(password):
            return jsonify({"success": False, "message": "La contraseña debe tener al menos 8 caracteres, una mayúscula y un número"}), 400
        if db_query("SELECT id FROM usuarios WHERE email = %s", (email,), one=True):
            return jsonify({"success": False, "message": "El correo electrónico ya está registrado"}), 409

        rol_cliente = db_query("SELECT id FROM roles WHERE codigo = 'ROLE_CLIENTE'", one=True)
        rol_id = rol_cliente["id"] if rol_cliente else 4
        db_exec("INSERT INTO usuarios (nombre, email, password, rol_id, estado) VALUES (%s, %s, %s, %s, 1)", (nombre, email, hashear_password(password), rol_id))
        return jsonify({"success": True, "message": "Cuenta creada correctamente"}), 200
    except Exception:
        return jsonify({"success": False, "message": "Error interno del servidor"}), 500

@app.route("/login", methods=["POST"])
def login():
    try:
        datos = request.get_json() or {}
        email = datos.get("email", "").strip()
        password = datos.get("password", "")

        if not email or not password:
            return jsonify({"success": False, "message": "Correo y contraseña obligatorios"}), 400
        ip = request.remote_addr or "local"
        if not reservar_intento(ip):
            response = jsonify(success=False, message="Demasiados intentos. Esperá 15 minutos antes de volver a intentar.")
            response.headers["Retry-After"] = str(LOGIN_WINDOW)
            return response, 429

        sql = """
            SELECT u.id, u.nombre, u.email, u.password, u.estado, u.rol_id,
                   u.direccion, u.telefono, r.codigo AS rol_codigo, r.nombre AS rol_nombre
            FROM usuarios u LEFT JOIN roles r ON u.rol_id = r.id WHERE u.email = %s
        """
        u = db_query(sql, (email,), one=True)
        if not u:
            return jsonify({"success": False, "message": "Usuario o contraseña incorrectos"}), 401
        if u["estado"] != 1:
            return jsonify({"success": False, "message": "Tu cuenta se encuentra suspendida"}), 403
        if not bcrypt.checkpw(password.encode("utf-8"), u["password"].encode("utf-8")):
            return jsonify({"success": False, "message": "Usuario o contraseña incorrectos"}), 401

        with intentos_lock:
            intentos_login.pop(ip, None)
        session.clear()
        session.permanent = True
        session["usuario_id"] = u["id"]
        session["rol_codigo"] = u["rol_codigo"]
        return jsonify({
            "success": True,
            "message": "Inicio de sesión exitoso",
            "usuario": {
                "id": u["id"], "nombre": u["nombre"], "email": u["email"], "rol_id": u["rol_id"],
                "rol_codigo": u["rol_codigo"] or "ROLE_CLIENTE", "rol_nombre": u["rol_nombre"] or "Cliente",
                "direccion": u["direccion"] or "", "telefono": u["telefono"] or ""
            }
        }), 200
    except Exception:
        return jsonify({"success": False, "message": "Error interno del servidor"}), 500

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True, "message": "Sesión cerrada correctamente"}), 200

@app.route("/recuperar", methods=["POST"])
def recuperar():
    try:
        datos = request.get_json() or {}
        email = datos.get("email", "").strip()
        if not email:
            return jsonify({"success": False, "message": "El correo es obligatorio"}), 400
        if not email_valido(email):
            return jsonify(success=False, message="El formato del correo electrónico es inválido"), 400
        # Comprobar configuración también para correos inexistentes evita revelar cuentas.
        if not os.getenv("SMTP_HOST") or not os.getenv("SMTP_FROM"):
            app.logger.error("Recuperación no disponible: falta configurar SMTP_HOST/SMTP_FROM")
            return jsonify(success=False, message="La recuperación por correo no está disponible temporalmente."), 503

        u = db_query("SELECT id FROM usuarios WHERE email = %s AND estado = 1", (email,), one=True)
        if u:
            token = secrets.token_urlsafe(32)
            expira = datetime.now() + timedelta(minutes=15)
            with transaccion() as cur:
                cur.execute("SELECT id FROM usuarios WHERE id = %s FOR UPDATE", (u["id"],))
                cur.fetchone()
                cur.execute("UPDATE recuperacion_tokens SET usado = 1 WHERE usuario_id = %s", (u["id"],))
                cur.execute("INSERT INTO recuperacion_tokens (usuario_id, token, expira_en, usado) VALUES (%s, %s, %s, 0)", (u["id"], token, expira))
            try:
                enviar_recuperacion(email, token)
            except Exception:
                # No anunciar entrega ni exponer la existencia de la cuenta si SMTP falla.
                db_exec("UPDATE recuperacion_tokens SET usado = 1 WHERE token = %s", (token,))
                app.logger.error("No se pudo enviar un correo de recuperación; revisar el servicio SMTP")

        return jsonify({"success": True, "message": "Si el correo coincide con una cuenta activa, recibirás un enlace de recuperación."}), 200
    except Exception:
        return jsonify({"success": False, "message": "Error interno del servidor"}), 500

@app.route("/restablecer/validar", methods=["POST"])
def validar_enlace():
    try:
        token = (request.get_json() or {}).get("token", "").strip()
        reg = db_query("SELECT id, expira_en, usado FROM recuperacion_tokens WHERE token = %s", (token,), one=True)
        if not reg or reg["usado"] or datetime.now() >= reg["expira_en"]:
            return jsonify(success=False, message="El enlace venció, ya fue utilizado o no es válido. Solicitá uno nuevo."), 400
        return jsonify(success=True, message="Enlace válido"), 200
    except Exception:
        return jsonify(success=False, message="No se pudo verificar el enlace. Intentá nuevamente."), 500


@app.route("/restablecer", methods=["POST"])
def restablecer():
    try:
        datos = request.get_json() or {}
        token = datos.get("token", "").strip()
        nueva = datos.get("password", "")

        if not token or not nueva:
            return jsonify({"success": False, "message": "Faltan datos obligatorios"}), 400
        if not password_segura(nueva):
            return jsonify({"success": False, "message": "La contraseña debe tener mínimo 8 caracteres, una mayúscula y un número"}), 400

        nuevo_hash = hashear_password(nueva)
        with transaccion() as cur:
            cur.execute("SELECT id, usuario_id, expira_en, usado FROM recuperacion_tokens WHERE token = %s FOR UPDATE", (token,))
            reg = cur.fetchone()
            if not reg or reg["usado"] == 1:
                return jsonify({"success": False, "message": "El enlace no es válido o ya fue utilizado"}), 400
            if datetime.now() >= reg["expira_en"]:
                return jsonify({"success": False, "message": "El enlace ha caducado. Solicitá uno nuevo"}), 400
            cur.execute("UPDATE usuarios SET password = %s WHERE id = %s", (nuevo_hash, reg["usuario_id"]))
            cur.execute("UPDATE recuperacion_tokens SET usado = 1 WHERE id = %s", (reg["id"],))
        return jsonify({"success": True, "message": "Contraseña restablecida correctamente"}), 200
    except Exception:
        return jsonify({"success": False, "message": "Error interno del servidor"}), 500

@app.route("/perfil", methods=["GET"])
@login_requerido
def obtener_perfil():
    u = request.usuario_actual
    return jsonify({
        "success": True,
        "perfil": {
            "id": u["id"], "nombre": u["nombre"], "email": u["email"],
            "direccion": u["direccion"] or "", "telefono": u["telefono"] or "",
            "rol_codigo": u["rol_codigo"] or "ROLE_CLIENTE", "rol_nombre": u["rol_nombre"] or "Cliente"
        }
    }), 200

@app.route("/perfil", methods=["PUT"])
@login_requerido
def actualizar_perfil():
    try:
        uid = request.usuario_actual["id"]
        datos = request.get_json() or {}
        nombre = datos.get("nombre", "").strip()
        direccion = datos.get("direccion", "").strip()
        telefono = datos.get("telefono", "").strip()

        if not nombre or len(nombre) < 3 or len(nombre) > 100:
            return jsonify({"success": False, "message": "El nombre debe tener entre 3 y 100 caracteres", "campo": "nombre"}), 400
        if not direccion or len(direccion) > 255:
            return jsonify({"success": False, "message": "La dirección es obligatoria y menor a 255 caracteres", "campo": "direccion"}), 400
        if not telefono or not validar_telefono(telefono):
            return jsonify({"success": False, "message": "El teléfono debe tener entre 8 y 15 dígitos numéricos", "campo": "telefono"}), 400

        db_exec("UPDATE usuarios SET nombre = %s, direccion = %s, telefono = %s WHERE id = %s", (nombre, direccion, telefono, uid))
        return jsonify({
            "success": True,
            "message": "Cambios guardados con éxito. La información de tu perfil fue actualizada.",
            "usuario": {"id": uid, "nombre": nombre, "direccion": direccion, "telefono": telefono}
        }), 200
    except Exception:
        return jsonify({"success": False, "message": "Error interno del servidor"}), 500

@app.route("/roles", methods=["GET"])
@requiere_rol("ROLE_ADMIN")
def listar_roles():
    try:
        roles = db_query("SELECT id, codigo, nombre, descripcion, activo, fecha_creacion FROM roles ORDER BY id ASC")
        return jsonify({"success": True, "roles": roles}), 200
    except Exception:
        return jsonify({"success": False, "message": "Error interno del servidor"}), 500

@app.route("/roles", methods=["POST"])
@requiere_rol("ROLE_ADMIN")
def crear_rol():
    try:
        datos = request.get_json() or {}
        codigo = datos.get("codigo", "").strip().upper()
        nombre = datos.get("nombre", "").strip()
        descripcion = datos.get("descripcion", "").strip()

        if not codigo or not re.match(r"^ROLE_[A-Z0-9_]+$", codigo):
            return jsonify({"success": False, "message": "El código debe comenzar con 'ROLE_' y contener solo mayúsculas, números o guiones bajos"}), 400
        if not nombre or len(nombre) > 100 or len(codigo) > 50 or len(descripcion) > 255:
            return jsonify({"success": False, "message": "Nombre obligatorio (máximo 100), código máximo 50 y descripción máximo 255 caracteres"}), 400
        if db_query("SELECT id FROM roles WHERE codigo = %s OR nombre = %s", (codigo, nombre), one=True):
            return jsonify({"success": False, "message": "Ya existe un rol con ese código o nombre"}), 409

        with transaccion() as cur:
            cur.execute("INSERT INTO roles (codigo, nombre, descripcion, activo) VALUES (%s, %s, %s, 1)", (codigo, nombre, descripcion))
            nuevo_id = cur.lastrowid
            registrar_auditoria(cur, "crear_rol", "roles", nuevo_id, None,
                                {"codigo": codigo, "nombre": nombre, "descripcion": descripcion, "activo": 1})
        return jsonify({
            "success": True, "message": "Rol creado correctamente",
            "rol": {"id": nuevo_id, "codigo": codigo, "nombre": nombre, "descripcion": descripcion, "activo": 1}
        }), 201
    except Exception:
        return jsonify({"success": False, "message": "Error interno del servidor"}), 500

@app.route("/roles/<int:rol_id>", methods=["PUT"])
@requiere_rol("ROLE_ADMIN")
def editar_rol(rol_id):
    try:
        datos = request.get_json() or {}
        with transaccion() as cur:
            cur.execute("SELECT id, codigo, nombre, descripcion, activo FROM roles WHERE id = %s FOR UPDATE", (rol_id,))
            rol = cur.fetchone()
            if not rol:
                return jsonify({"success": False, "message": "Rol no encontrado"}), 404
            if "codigo" in datos and datos["codigo"].strip().upper() != rol["codigo"]:
                return jsonify({"success": False, "message": "El código del rol es inmutable y no puede modificarse"}), 400

            nombre = datos.get("nombre", rol["nombre"]).strip()
            descripcion = datos.get("descripcion", rol["descripcion"]).strip()
            activo = datos.get("activo", rol["activo"])

            if type(activo) is not int or activo not in (0, 1):
                return jsonify(success=False, message="Estado del rol inválido"), 400
            if len(nombre) > 100 or len(descripcion) > 255:
                return jsonify(success=False, message="Nombre o descripción demasiado largos"), 400
            if not nombre:
                return jsonify({"success": False, "message": "El nombre del rol no puede quedar vacío"}), 400
            cur.execute("SELECT id FROM roles WHERE nombre = %s AND id != %s", (nombre, rol_id))
            if cur.fetchone():
                return jsonify({"success": False, "message": "Ya existe otro rol con ese nombre"}), 409

            if rol["activo"] == 1 and activo == 0:
                if rol["codigo"] == "ROLE_ADMIN":
                    return jsonify({"success": False, "message": "No se puede desactivar el rol de Administrador"}), 400
                cur.execute("SELECT COUNT(*) AS total FROM usuarios WHERE rol_id = %s", (rol_id,))
                conteo = cur.fetchone()
                if conteo and conteo["total"] > 0:
                    return jsonify({"success": False, "message": f"No se puede desactivar: hay {conteo['total']} usuario(s) asignado(s) a este rol."}), 400

            cur.execute("UPDATE roles SET nombre = %s, descripcion = %s, activo = %s WHERE id = %s", (nombre, descripcion, activo, rol_id))
            registrar_auditoria(cur, "editar_rol", "roles", rol_id, rol, {"codigo": rol["codigo"], "nombre": nombre, "descripcion": descripcion, "activo": activo})
        return jsonify({
            "success": True, "message": "Rol actualizado correctamente",
            "rol": {"id": rol_id, "codigo": rol["codigo"], "nombre": nombre, "descripcion": descripcion, "activo": activo}
        }), 200
    except Exception:
        return jsonify({"success": False, "message": "Error interno del servidor"}), 500

@app.route("/usuarios", methods=["GET"])
@requiere_rol("ROLE_ADMIN")
def listar_usuarios():
    try:
        sql = """
            SELECT u.id, u.nombre, u.email, u.rol_id, u.direccion, u.telefono,
                   u.estado, u.fecha_baja, u.fecha_creacion,
                   r.codigo AS rol_codigo, r.nombre AS rol_nombre
            FROM usuarios u LEFT JOIN roles r ON u.rol_id = r.id ORDER BY u.id DESC
        """
        usuarios = db_query(sql)
        for u in usuarios:
            if u["fecha_creacion"]:
                u["fecha_creacion"] = u["fecha_creacion"].strftime("%Y-%m-%d %H:%M")
            if u["fecha_baja"]:
                u["fecha_baja"] = u["fecha_baja"].strftime("%Y-%m-%d %H:%M")
        return jsonify({"success": True, "usuarios": usuarios}), 200
    except Exception:
        return jsonify({"success": False, "message": "Error interno del servidor"}), 500

@app.route("/usuarios/<int:usuario_id>/rol", methods=["PUT"])
@requiere_rol("ROLE_ADMIN")
def asignar_rol_usuario(usuario_id):
    try:
        datos = request.get_json() or {}
        nuevo_rol_id = datos.get("rol_id")
        if type(nuevo_rol_id) is not int or nuevo_rol_id <= 0:
            return jsonify({"success": False, "message": "Debe especificar el nuevo rol_id"}), 400

        with transaccion() as cur:
            cur.execute("SELECT id FROM roles WHERE codigo = 'ROLE_ADMIN' FOR UPDATE")
            rol_admin = cur.fetchone()
            cur.execute("SELECT id, nombre, email, rol_id FROM usuarios WHERE id = %s FOR UPDATE", (usuario_id,))
            u = cur.fetchone()
            if not u:
                return jsonify({"success": False, "message": "Usuario no encontrado"}), 404

            cur.execute("SELECT id, codigo, nombre, activo FROM roles WHERE id = %s", (nuevo_rol_id,))
            rol = cur.fetchone()
            if not rol:
                return jsonify({"success": False, "message": "El rol especificado no existe"}), 404
            if rol["activo"] != 1:
                return jsonify({"success": False, "message": "No se puede asignar un rol que se encuentra inactivo"}), 400

            if rol_admin and u["rol_id"] == rol_admin["id"] and nuevo_rol_id != rol_admin["id"]:
                cur.execute("SELECT COUNT(*) AS total FROM usuarios WHERE rol_id = %s AND estado = 1", (rol_admin["id"],))
                admins = cur.fetchone()
                if admins["total"] <= 1:
                    return jsonify({"success": False, "message": "No podés remover el rol al único administrador activo del sistema"}), 400

            cur.execute("UPDATE usuarios SET rol_id = %s WHERE id = %s", (nuevo_rol_id, usuario_id))
            registrar_auditoria(cur, "asignar_rol", "usuarios", usuario_id, {"rol_id": u["rol_id"]}, {"rol_id": nuevo_rol_id})
        return jsonify({"success": True, "message": f"Rol de {u['nombre']} actualizado a {rol['nombre']}", "usuario_id": usuario_id, "rol": rol}), 200
    except Exception:
        return jsonify({"success": False, "message": "Error interno del servidor"}), 500

@app.route("/usuarios/<int:usuario_id>/estado", methods=["PUT"])
@requiere_rol("ROLE_ADMIN")
def cambiar_estado_usuario(usuario_id):
    try:
        datos = request.get_json() or {}
        nuevo_estado = datos.get("estado")
        if type(nuevo_estado) is not int or nuevo_estado not in (0, 1):
            return jsonify({"success": False, "message": "Estado inválido. Debe ser 0 o 1"}), 400

        with transaccion() as cur:
            cur.execute("SELECT id FROM roles WHERE codigo = 'ROLE_ADMIN' FOR UPDATE")
            rol_admin = cur.fetchone()
            cur.execute("SELECT id, nombre, email, estado, rol_id, fecha_baja FROM usuarios WHERE id = %s FOR UPDATE", (usuario_id,))
            u = cur.fetchone()
            if not u:
                return jsonify({"success": False, "message": "Usuario no encontrado"}), 404

            if nuevo_estado == 0:
                if rol_admin and u["rol_id"] == rol_admin["id"]:
                    cur.execute("SELECT COUNT(*) AS total FROM usuarios WHERE rol_id = %s AND estado = 1", (rol_admin["id"],))
                    admins = cur.fetchone()
                    if admins["total"] <= 1:
                        return jsonify({"success": False, "message": "Operación cancelada: No podés desactivar al único administrador activo del sistema."}), 400
                fecha_baja = datetime.now()
                cur.execute("UPDATE usuarios SET estado = 0, fecha_baja = %s WHERE id = %s", (fecha_baja, usuario_id))
                mensaje = f"La cuenta de {u['nombre']} fue desactivada correctamente (baja lógica)."
            else:
                fecha_baja = None
                cur.execute("UPDATE usuarios SET estado = 1, fecha_baja = NULL WHERE id = %s", (usuario_id,))
                mensaje = f"La cuenta de {u['nombre']} fue reactivada con éxito."

            registrar_auditoria(cur, "cambiar_estado", "usuarios", usuario_id, {"estado": u["estado"], "fecha_baja": u["fecha_baja"]}, {"estado": nuevo_estado, "fecha_baja": fecha_baja})
        return jsonify({"success": True, "message": mensaje, "usuario_id": usuario_id, "nuevo_estado": nuevo_estado}), 200
    except Exception:
        return jsonify({"success": False, "message": "Error interno del servidor"}), 500

if __name__ == "__main__":
    app.run(host="localhost", port=int(os.getenv("PORT", "3000")), debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
