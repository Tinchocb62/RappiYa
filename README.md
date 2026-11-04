# RappiYa

Aplicación web de práctica orientada a la gestión de usuarios, con registro, inicio de sesión y recuperación de contraseña.

El proyecto utiliza un frontend desarrollado con HTML, CSS y JavaScript, un backend construido con Flask y una base de datos MySQL.

---

## 📌 Funcionalidades

### Registro de usuarios
- Registro mediante nombre, correo electrónico y contraseña.
- Validación de campos obligatorios.
- Validación del formato del correo electrónico.
- Validación de seguridad de la contraseña:
  - mínimo 8 caracteres;
  - al menos una letra mayúscula;
  - al menos un número.
- Verificación de que el correo no esté registrado.
- Almacenamiento de contraseñas utilizando **bcrypt**.

### Inicio de sesión
- Autenticación mediante correo y contraseña.
- Verificación de la contraseña utilizando bcrypt.
- Control del estado de la cuenta.
- Mensajes de error para credenciales incorrectas.
- Almacenamiento temporal de los datos del usuario autenticado mediante `sessionStorage`.

### Recuperación de contraseña
- Solicitud de recuperación mediante correo electrónico.
- Generación de un token seguro.
- Token con una duración de 15 minutos.
- Invalidación de tokens anteriores no utilizados.
- Restablecimiento de contraseña utilizando el token.
- Los tokens se marcan como utilizados después de completar el cambio.



---

## 🛠️ Tecnologías utilizadas

### Frontend
- HTML5
- CSS3
- JavaScript
- Fetch API
- `sessionStorage`

### Backend
- Python
- Flask
- Flask-CORS
- MySQL Connector/Python
- bcrypt

### Base de datos
- MySQL

---

## 📁 Estructura del proyecto

```text
RappiYa/
├── backend/
│   └── app.py
│
├── home/
│   ├── index.html
│   ├── registro.html
│   ├── registro.js
│   ├── recuperarpass.html
│   ├── restablecerpass.html
│   └── style.css
│
├── database.sql
├── .gitignore
└── README.md
```

---

## ⚙️ Requisitos

Para ejecutar el proyecto localmente necesitás:

- Python 3
- MySQL
- Un navegador web
- Un servidor local para el frontend, por ejemplo **Live Server** de Visual Studio Code

---

## 🗄️ Configuración de la base de datos

El proyecto incluye el archivo `database.sql`, que crea la base de datos `rappiya` y las tablas necesarias.

### 1. Crear la base de datos

Ejecutá el contenido de `database.sql` en MySQL, phpMyAdmin o una herramienta equivalente.

La estructura principal incluye:

- `usuarios`: almacena los usuarios registrados.
- `recuperacion_tokens`: almacena los tokens utilizados para recuperar contraseñas.

---

## 🐍 Configuración del backend

Ingresá a la carpeta del backend:

```bash
cd backend
```

Instalá las dependencias:

```bash
pip install flask flask-cors mysql-connector-python bcrypt
```

Luego iniciá el servidor:

```bash
python app.py
```

El backend queda disponible en:

```text
http://localhost:3000
```

La ruta principal:

```text
GET http://localhost:3000/
```

responde con un mensaje indicando que el backend está funcionando.

---

## 🌐 Ejecutar el frontend

El frontend se encuentra dentro de la carpeta `home`.

La forma recomendada de ejecutarlo durante el desarrollo es mediante un servidor local, por ejemplo **Live Server**.

Por defecto, el flujo de recuperación genera enlaces utilizando:

```text
http://localhost:5500/home/restablecerpass.html?token=...
```

Por lo tanto, es importante que el frontend esté servido correctamente desde un servidor local.

---

## 🔌 Endpoints de la API

### Registro

```http
POST /registro
```

Ejemplo de datos enviados:

```json
{
  "name": "Juan Pérez",
  "email": "juan@email.com",
  "password": "ClaveSegura1"
}
```

### Inicio de sesión

```http
POST /login
```

Ejemplo:

```json
{
  "email": "juan@email.com",
  "password": "ClaveSegura1"
}
```

### Solicitar recuperación

```http
POST /recuperar
```

Ejemplo:

```json
{
  "email": "juan@email.com"
}
```

### Restablecer contraseña

```http
POST /restablecer
```

Ejemplo:

```json
{
  "token": "TOKEN_GENERADO",
  "password": "NuevaClave1"
}
```

---

## 🔐 Seguridad implementada

El proyecto incorpora algunas medidas básicas de seguridad:

- Contraseñas almacenadas mediante **bcrypt**.
- Tokens de recuperación generados con `secrets.token_urlsafe()`.
- Expiración de tokens a los 15 minutos.
- Tokens de recuperación de un solo uso.
- Invalidación de tokens anteriores al solicitar una nueva recuperación.
- Respuesta genérica en el endpoint de recuperación para evitar revelar si un correo está registrado.
- Validación tanto en frontend como en backend.

---

## ⚠️ Consideraciones para desarrollo

Este proyecto está pensado para un entorno local y académico. Antes de utilizarlo en producción sería necesario, entre otras cosas:

- mover las credenciales de MySQL a variables de entorno;
- configurar correctamente CORS;
- implementar un servicio real de envío de correos;
- utilizar HTTPS;
- incorporar manejo de sesiones/autenticación más robusto;
- agregar archivos de dependencias como `requirements.txt`;
- mejorar la configuración de producción de Flask.

---

## 🎯 Objetivo del proyecto

RappiYa fue desarrollado como proyecto de práctica para aplicar conceptos de:

- desarrollo web;
- validación de formularios;
- programación frontend y backend;
- creación y consumo de APIs;
- conexión con bases de datos MySQL;
- autenticación de usuarios;
- hashing de contraseñas;
- recuperación segura de cuentas.

---

Repositorio:  
https://github.com/Tinchocb62/RappiYa
