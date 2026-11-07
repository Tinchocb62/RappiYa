
window.RAPPIYA_API = location.port === "5500" ? "http://localhost:3000" : location.origin;
window.apiFetch = async function (url, options = {}) {
  if (["POST", "PUT", "PATCH", "DELETE"].includes((options.method || "GET").toUpperCase()) && !options.body) {
    options = { ...options, headers: { ...options.headers, "Content-Type": "application/json" }, body: "{}" };
  }
  const response = await fetch(url, { ...options, credentials: "include" });
  const path = new URL(url, location.href).pathname;
  if (response.status === 401 && /^\/(perfil|roles|usuarios)(\/|$)/.test(path)) {
    sessionStorage.removeItem("usuario");
    location.replace("index.html");
    throw new Error("La sesión venció. Iniciá sesión nuevamente.");
  }
  return response;
};

const accessScript = document.currentScript;
if (accessScript.dataset.protected !== undefined) {
  document.documentElement.style.visibility = "hidden";
  window.sessionReady = (async () => {
    try {
      const response = await window.apiFetch(`${window.RAPPIYA_API}/perfil`);
      if (!response.ok) throw new Error("No se pudo verificar tu sesión.");
      const data = await response.json();
      const user = data.perfil;
      sessionStorage.setItem("usuario", JSON.stringify(user));
      if (accessScript.dataset.admin !== undefined && user.rol_codigo !== "ROLE_ADMIN") {
        const title = document.createElement("h1");
        title.textContent = "Acceso denegado";
        const message = document.createElement("p");
        message.textContent = "No tenés permisos para ver esta sección.";
        const back = document.createElement("a");
        back.href = "panel.html";
        back.textContent = "Volver al inicio";
        document.body.replaceChildren(title, message, back);
        return null;
      }
      return user;
    } catch (error) {
      if (!location.pathname.endsWith("index.html")) {
        const message = document.createElement("p");
        message.textContent = "No se pudo verificar la sesión. Volvé a iniciar sesión o revisá la conexión.";
        const back = document.createElement("a");
        back.href = "index.html";
        back.textContent = "Ir al inicio de sesión";
        document.body.replaceChildren(message, back);
      }
      return null;
    } finally {
      document.getElementById("sessionGuard")?.remove();
      document.documentElement.style.visibility = "";
    }
  })();
}
