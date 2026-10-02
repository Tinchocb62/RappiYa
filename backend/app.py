from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import bcrypt
import re
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# =========================================================
# CONEXIÓN A MYSQL
# =========================================================
def conectar_bd():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="rappiya",
        port=3306
    )

# Funciones auxiliares de validación
def email_valido(email):
    patron = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(patron, email) is not None

def password_segura(password):
    # Mínimo 8 caracteres, al menos una mayúscula y un número
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    return True

# =========================================================
# RUTA PRINCIPAL
# =========================================================
@app.route("/", methods=["GET"])
def inicio():
    return jsonify({"mensaje": "Backend de RappiYa funcionando"})

# =========================================================
# REGISTRO DE USUARIO (HU01 y HU02)
# =========================================================
@app.route("/registro", methods=["POST"])
def registro():
    try:
        datos = request.get_json()
        if not datos:
            return jsonify({"success": False, "message": "No se recibieron datos"}), 400

        nombre = datos.get("name", "").strip()
        email = datos.get("email", "").strip()
        password = datos.get("password", "")

        # Validaciones de campos obligatorios
        if not nombre or not email or not password:
            return jsonify({"success": False, "message": "Todos los campos son obligatorios"}), 400

        # Validación de formato de email
        if not email_valido(email):
            return jsonify({"success": False, "message": "El formato del correo electrónico es inválido"}), 400

        # Validación de seguridad de la contraseña
        if not password_segura(password):
            return jsonify({
                "success": False,
                "message": "La contraseña debe tener al menos 8 caracteres, una mayúscula y un número"
            }), 400

        conexion = conectar_bd()
        cursor = conexion.cursor()

        # Verificar si el correo ya existe
        cursor.execute("SELECT id FROM usuarios WHERE email = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            conexion.close()
            return jsonify({"success": False, "message": "El correo electrónico ya está registrado"}), 409

        # Hashear la contraseña con salt usando bcrypt
        salt = bcrypt.gensalt()
        password_hasheada = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

        # Guardar usuario
        sql = "INSERT INTO usuarios (nombre, email, password, estado) VALUES (%s, %s, %s, 1)"
        cursor.execute(sql, (nombre, email, password_hasheada))
        conexion.commit()

        cursor.close()
        conexion.close()

        return jsonify({"success": True, "message": "Cuenta creada correctamente"}), 200

    except Exception as error:
        print("Error en registro:", error)
        return jsonify({"success": False, "message": "Error interno del servidor"}), 500

# =========================================================
# INICIO DE SESIÓN Y VERIFICACIÓN (HU03 y HU04)
# =========================================================
@app.route("/login", methods=["POST"])
def login():
    try:
        datos = request.get_json()
        if not datos:
            return jsonify({"success": False, "message": "No se recibieron credenciales"}), 400

        email = datos.get("email", "").strip()
        password = datos.get("password", "")

        if not email or not password:
            return jsonify({"success": False, "message": "Correo y contraseña obligatorios"}), 400

        conexion = conectar_bd()
        cursor = conexion.cursor(dictionary=True)

        cursor.execute("SELECT id, nombre, email, password, estado FROM usuarios WHERE email = %s", (email,))
        usuario = cursor.fetchone()

        cursor.close()
        conexion.close()

        # Si el usuario no existe, devolvemos error genérico por seguridad
        if not usuario:
            return jsonify({"success": False, "message": "Credenciales inválidas"}), 401

        # Control de cuenta inactiva
        if usuario["estado"] != 1:
            return jsonify({"success": False, "message": "Tu cuenta se encuentra deshabilitada"}), 403

        # Verificar hash de contraseña
        coincide = bcrypt.checkpw(password.encode("utf-8"), usuario["password"].encode("utf-8"))
        if not coincide:
            return jsonify({"success": False, "message": "Credenciales inválidas"}), 401

        return jsonify({
            "success": True,
            "message": "Inicio de sesión exitoso",
            "usuario": {
                "id": usuario["id"],
                "nombre": usuario["nombre"],
                "email": usuario["email"]
            }
        }), 200

    except Exception as error:
        print("Error en login:", error)
        return jsonify({"success": False, "message": "Error interno del servidor"}), 500

# =========================================================
# SOLICITUD DE RECUPERACIÓN (HU05)
# =========================================================
@app.route("/recuperar", methods=["POST"])
def recuperar():
    try:
        datos = request.get_json()
        email = datos.get("email", "").strip()

        if not email:
            return jsonify({"success": False, "message": "El correo es obligatorio"}), 400

        conexion = conectar_bd()
        cursor = conexion.cursor(dictionary=True)

        cursor.execute("SELECT id FROM usuarios WHERE email = %s AND estado = 1", (email,))
        usuario = cursor.fetchone()

        if usuario:
            # Generar token seguro y fecha de expiración (15 minutos)
            token = secrets.token_urlsafe(32)
            expira_en = datetime.now() + timedelta(minutes=15)

            # Invalidar tokens viejos sin usar para este usuario
            cursor.execute("UPDATE recuperacion_tokens SET usado = 1 WHERE usuario_id = %s", (usuario["id"],))

            # Guardar nuevo token
            cursor.execute(
                "INSERT INTO recuperacion_tokens (usuario_id, token, expira_en, usado) VALUES (%s, %s, %s, 0)",
                (usuario["id"], token, expira_en)
            )
            conexion.commit()

            # Simulación de despacho de correo por consola
            url_recuperacion = f"http://localhost:5500/home/restablecerpass.html?token={token}"
            print("====================================================")
            print(f"ENLACE DE RECUPERACIÓN PARA {email}:")
            print(url_recuperacion)
            print("====================================================")

        cursor.close()
        conexion.close()

        # Respuesta genérica para evitar la enumeración de usuarios
        return jsonify({
            "success": True,
            "message": "Si el correo coincide con una cuenta activa, recibirás un enlace de recuperación."
        }), 200

    except Exception as error:
        print("Error en recuperación:", error)
        return jsonify({"success": False, "message": "Error interno del servidor"}), 500

# =========================================================
# RESTABLECER CONTRASEÑA CON TOKEN (HU05)
# =========================================================
@app.route("/restablecer", methods=["POST"])
def restablecer():
    try:
        datos = request.get_json()
        token = datos.get("token", "").strip()
        nueva_password = datos.get("password", "")

        if not token or not nueva_password:
            return jsonify({"success": False, "message": "Faltan datos obligatorios"}), 400

        if not password_segura(nueva_password):
            return jsonify({
                "success": False,
                "message": "La contraseña debe tener mínimo 8 caracteres, una mayúscula y un número"
            }), 400

        conexion = conectar_bd()
        cursor = conexion.cursor(dictionary=True)

        # Validar vigencia del token
        cursor.execute(
            "SELECT id, usuario_id, expira_en, usado FROM recuperacion_tokens WHERE token = %s",
            (token,)
        )
        registro_token = cursor.fetchone()

        if not registro_token or registro_token["usado"] == 1:
            cursor.close()
            conexion.close()
            return jsonify({"success": False, "message": "El enlace no es válido o ya fue utilizado"}), 400

        if datetime.now() > registro_token["expira_en"]:
            cursor.close()
            conexion.close()
            return jsonify({"success": False, "message": "El enlace ha caducado. Solicitá uno nuevo"}), 400

        # Hashear la nueva contraseña
        salt = bcrypt.gensalt()
        password_hasheada = bcrypt.hashpw(nueva_password.encode("utf-8"), salt).decode("utf-8")

        # Actualizar contraseña del usuario y marcar token como usado
        cursor.execute(
            "UPDATE usuarios SET password = %s WHERE id = %s",
            (password_hasheada, registro_token["usuario_id"])
        )
        cursor.execute(
            "UPDATE recuperacion_tokens SET usado = 1 WHERE id = %s",
            (registro_token["id"],)
        )
        conexion.commit()

        cursor.close()
        conexion.close()

        return jsonify({"success": True, "message": "Contraseña restablecida correctamente"}), 200

    except Exception as error:
        print("Error al restablecer:", error)
        return jsonify({"success": False, "message": "Error interno del servidor"}), 500

if __name__ == "__main__":
    app.run(host="localhost", port=3000, debug=True)