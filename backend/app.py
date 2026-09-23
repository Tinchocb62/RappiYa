
from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector

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


# =========================================================
# RUTA PRINCIPAL
# =========================================================

@app.route("/", methods=["GET"])
def inicio():

    return jsonify({
        "mensaje": "Backend de RappiYa funcionando"
    })


# =========================================================
# REGISTRO DE USUARIO
# =========================================================

@app.route("/registro", methods=["POST"])
def registro():

    try:

        # Obtener datos enviados por JavaScript
        datos = request.get_json()

        if not datos:
            return jsonify({
                "success": False,
                "message": "No se recibieron datos"
            }), 400


        nombre = datos.get("name")
        email = datos.get("email")
        password = datos.get("password")


        # Comprobar campos
        if not nombre or not email or not password:

            return jsonify({
                "success": False,
                "message": "Todos los campos son obligatorios"
            }), 400


        # Conectar a MySQL
        conexion = conectar_bd()

        cursor = conexion.cursor()


        # Comprobar si el email ya existe
        cursor.execute(
            "SELECT id FROM usuarios WHERE email = %s",
            (email,)
        )

        usuario_existente = cursor.fetchone()


        if usuario_existente:

            cursor.close()
            conexion.close()

            return jsonify({
                "success": False,
                "message": "El correo electrónico ya está registrado"
            }), 409


        # Insertar usuario
        sql = """
            INSERT INTO usuarios
            (nombre, email, password)
            VALUES (%s, %s, %s)
        """

        valores = (
            nombre,
            email,
            password
        )


        cursor.execute(sql, valores)

        conexion.commit()


        cursor.close()
        conexion.close()


        print("Usuario registrado:", email)


        return jsonify({
            "success": True,
            "message": "Cuenta creada correctamente"
        }), 200


    except mysql.connector.Error as error:

        print("Error de MySQL:", error)

        return jsonify({
            "success": False,
            "message": "Error al conectar con la base de datos"
        }), 500


    except Exception as error:

        print("Error:", error)

        return jsonify({
            "success": False,
            "message": "Error interno del servidor"
        }), 500


# =========================================================
# INICIAR SERVIDOR
# =========================================================

if __name__ == "__main__":

    app.run(
        host="localhost",
        port=3000,
        debug=True
    )

