
const formulario = document.getElementById("registroForm");
const mensaje = document.getElementById("mensaje");


formulario.addEventListener("submit", async function (event) {

    // Evita que la página se recargue
    event.preventDefault();


    // Obtener datos
    const nombre =
        document.getElementById("nombre").value.trim();

    const email =
        document.getElementById("email").value.trim();

    const password =
        document.getElementById("password").value;

    const confirmPassword =
        document.getElementById("confirmPassword").value;


    // =====================================================
    // VALIDAR CONTRASEÑAS
    // =====================================================

    if (password !== confirmPassword) {

        mensaje.textContent =
            "Las contraseñas no coinciden";

        return;
    }


    // =====================================================
    // ENVIAR DATOS A PYTHON
    // =====================================================

    try {

        const respuesta = await fetch(
            "http://localhost:3000/registro",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({

                    name: nombre,

                    email: email,

                    password: password

                })
            }
        );


        // Obtener respuesta del backend
        const datos = await respuesta.json();


        // =================================================
        // RESPUESTA EXITOSA
        // =================================================

        if (datos.success) {

            mensaje.textContent =
                "Cuenta creada correctamente";


            formulario.reset();


        } else {

            // Error enviado por Python
            mensaje.textContent =
                datos.message;

        }


    } catch (error) {

        console.error(
            "Error al conectar con el backend:",
            error
        );


        mensaje.textContent =
            "No se pudo conectar con el servidor";

    }

});

