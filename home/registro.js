const formulario = document.getElementById("registroForm");
const mensajeGeneral = document.getElementById("mensaje");

// Inputs
const inputNombre = document.getElementById("nombre");
const inputEmail = document.getElementById("email");
const inputPassword = document.getElementById("password");
const inputConfirmPassword = document.getElementById("confirmPassword");

// Spans de error
const errorNombre = document.getElementById("error-nombre");
const errorEmail = document.getElementById("error-email");
const errorPassword = document.getElementById("error-password");
const errorConfirmPassword = document.getElementById("error-confirmPassword");

// Funciones para prender y apagar los errores
function mostrarError(input, span, texto) {
    input.classList.add("input-error");
    span.textContent = texto;
    span.classList.add("activo");
}

function limpiarError(input, span) {
    input.classList.remove("input-error");
    span.textContent = "";
    span.classList.remove("activo");
}

// Limpiar el cartel rojo apenas el usuario empieza a tipear
inputNombre.addEventListener("input", () => limpiarError(inputNombre, errorNombre));
inputEmail.addEventListener("input", () => limpiarError(inputEmail, errorEmail));
inputPassword.addEventListener("input", () => limpiarError(inputPassword, errorPassword));
inputConfirmPassword.addEventListener("input", () => limpiarError(inputConfirmPassword, errorConfirmPassword));

formulario.addEventListener("submit", async function (event) {
    event.preventDefault();
    mensajeGeneral.textContent = "";
    mensajeGeneral.className = "";

    let hayErrores = false;

    // 1. Validar Nombre
    if (inputNombre.value.trim() === "") {
        mostrarError(inputNombre, errorNombre, "El nombre es obligatorio");
        hayErrores = true;
    }

    // 2. Validar Email
    const patronEmail = /^[\w\.-]+@[\w\.-]+\.\w+$/;
    if (inputEmail.value.trim() === "") {
        mostrarError(inputEmail, errorEmail, "El correo electrónico es obligatorio");
        hayErrores = true;
    } else if (!patronEmail.test(inputEmail.value.trim())) {
        mostrarError(inputEmail, errorEmail, "Ingresá un correo válido (ej: usuario@correo.com)");
        hayErrores = true;
    }

    // 3. Validar Contraseña
    const pass = inputPassword.value;
    if (pass === "") {
        mostrarError(inputPassword, errorPassword, "La contraseña es obligatoria");
        hayErrores = true;
    } else if (pass.length < 8) {
        mostrarError(inputPassword, errorPassword, "Debe tener al menos 8 caracteres");
        hayErrores = true;
    } else if (!/[A-Z]/.test(pass)) {
        mostrarError(inputPassword, errorPassword, "Debe incluir al menos una mayúscula");
        hayErrores = true;
    } else if (!/[0-9]/.test(pass)) {
        mostrarError(inputPassword, errorPassword, "Debe incluir al menos un número");
        hayErrores = true;
    }

    // 4. Validar Confirmación
    if (inputConfirmPassword.value === "") {
        mostrarError(inputConfirmPassword, errorConfirmPassword, "Repetí tu contraseña");
        hayErrores = true;
    } else if (pass !== inputConfirmPassword.value) {
        mostrarError(inputConfirmPassword, errorConfirmPassword, "Las contraseñas no coinciden");
        hayErrores = true;
    }

    if (hayErrores) return;

    // Enviar datos al backend
    try {
        const respuesta = await fetch("http://localhost:3000/registro", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name: inputNombre.value.trim(),
                email: inputEmail.value.trim(),
                password: pass
            })
        });

        const datos = await respuesta.json();

        if (datos.success) {
            mensajeGeneral.className = "exito";
            mensajeGeneral.textContent = "¡Cuenta creada correctamente! Redirigiendo...";
            formulario.reset();
            setTimeout(() => {
                window.location.href = "index.html";
            }, 1800);
        } else {
            // Si el correo ya existe, mostramos el error abajo del campo de email
            if (datos.message.includes("correo")) {
                mostrarError(inputEmail, errorEmail, datos.message);
            } else {
                mensajeGeneral.className = "error";
                mensajeGeneral.textContent = datos.message;
            }
        }
    } catch (error) {
        mensajeGeneral.className = "error";
        mensajeGeneral.textContent = "No se pudo conectar con el servidor";
    }
});