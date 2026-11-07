window.sessionReady.then((user) => {
  if (!user) return;
  const API = window.RAPPIYA_API;
  const $ = id => document.getElementById(id);
  const esAdmin = user.rol_codigo === "ROLE_ADMIN";

  let listaUsuarios = [], listaRoles = [], userToDeactivate = null, editingRoleId = null, currentFilter = "all";

  const esc = s => String(s || "").replace(/[&<>"']/g, m => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]));
  const iniciales = n => {
    const p = (n || "U").trim().split(" ");
    return (p.length >= 2 ? p[0][0] + p[1][0] : n.substring(0, 2)).toUpperCase();
  };

  // --- Inicialización de Interfaz y Datos de Usuario ---
  function initUser() {
    $("sidebarAvatar").textContent = iniciales(user.nombre);
    $("sidebarUserName").textContent = user.nombre || "Usuario";
    $("sidebarUserRole").textContent = user.rol_nombre || "Cliente";
    $("roleBadge").textContent = `Rol: ${user.rol_nombre || "Cliente"}`;
    $("adminSectionHeader").hidden = !esAdmin;
    $("tabUsers").hidden = !esAdmin;
    $("tabRoles").hidden = !esAdmin;

    $("fullName").value = user.nombre || "";
    $("email").value = user.email || "";
    $("address").value = user.direccion || "";
    $("phone").value = user.telefono || "";
  }
  initUser();

  // --- Navegación por Pestañas ---
  function mostrarSeccion(sec) {
    if ((sec === "users" || sec === "roles") && !esAdmin) sec = "profile";
    $("profilePage").hidden = sec !== "profile";
    $("usersPage").hidden = sec !== "users";
    $("rolesPage").hidden = sec !== "roles";
    $("tabProfile").classList.toggle("selected", sec === "profile");
    $("tabUsers").classList.toggle("selected", sec === "users");
    $("tabRoles").classList.toggle("selected", sec === "roles");
    location.hash = sec;
    if (sec === "users") cargarUsuarios();
    if (sec === "roles") { cargarRoles(); cargarUsuarios(); }
  }

  $("tabProfile").onclick = () => mostrarSeccion("profile");
  $("tabUsers").onclick = () => mostrarSeccion("users");
  $("tabRoles").onclick = () => mostrarSeccion("roles");

  const initialTab = (location.hash || "").replace("#", "");
  mostrarSeccion(["profile", "users", "roles"].includes(initialTab) ? initialTab : "profile");

  // --- Mi Perfil ---
  $("profileForm").onsubmit = async (e) => {
    e.preventDefault();
    const nombre = $("fullName").value.trim(), direccion = $("address").value.trim(), telefono = $("phone").value.trim();
    if (nombre.length < 3 || !direccion || !telefono) {
      $("profileError").hidden = false;
      $("profileErrorText").textContent = "Todos los campos obligatorios deben ser completados.";
      return;
    }
    try {
      const res = await apiFetch(`${API}/perfil`, {
        method: "PUT",
        body: JSON.stringify({ nombre, direccion, telefono })
      });
      const data = await res.json();
      if (data.success) {
        user.nombre = nombre;
        user.direccion = direccion;
        user.telefono = telefono;
        initUser();
        $("profileSuccess").hidden = false;
        $("profileError").hidden = true;
      } else {
        $("profileError").hidden = false;
        $("profileErrorText").textContent = data.message || "Error al actualizar";
      }
    } catch {
      $("profileError").hidden = false;
      $("profileErrorText").textContent = "Error de conexión";
    }
  };

  $("cancelProfile").onclick = initUser;

  // --- Gestión de Usuarios ---
  async function cargarUsuarios() {
    try {
      const res = await apiFetch(`${API}/usuarios`);
      const data = await res.json();
      if (data.success) {
        listaUsuarios = data.usuarios;
        renderizarUsuarios();
        renderizarAsignacionRoles();
      }
    } catch {}
  }

  function renderizarUsuarios() {
    const items = listaUsuarios.filter(u => currentFilter === "all" ? true : (currentFilter === "active" ? u.estado === 1 : u.estado === 0));
    $("usersTable").innerHTML = items.length ? items.map(u => `
      <tr>
        <td><div class="user-cell"><div class="avatar">${iniciales(u.nombre)}</div><div><div class="user-name">${esc(u.nombre)}</div><div class="user-email">${esc(u.email)}</div></div></div></td>
        <td>${esc(u.rol_nombre || "Cliente")}</td>
        <td>${esc(u.fecha_creacion || "-")}</td>
        <td><span class="status ${u.estado ? "active" : "inactive"}">${u.estado ? "Activa" : "Inactiva"}</span></td>
        <td><button class="action-btn ${u.estado ? "action-danger" : "action-success"}" data-user-id="${u.id}" data-action="${u.estado ? "deactivate" : "activate"}">${u.estado ? "Desactivar" : "Reactivar"}</button></td>
      </tr>
    `).join("") : '<tr><td colspan="5" style="text-align:center;padding:20px;">Sin usuarios</td></tr>';
  }

  document.querySelectorAll("[data-filter]").forEach(btn => {
    btn.onclick = () => {
      currentFilter = btn.dataset.filter;
      document.querySelectorAll("[data-filter]").forEach(b => b.classList.toggle("selected", b === btn));
      renderizarUsuarios();
    };
  });

  $("usersTable").onclick = (e) => {
    const btn = e.target.closest("[data-user-id]");
    if (!btn) return;
    const u = listaUsuarios.find(x => x.id === Number(btn.dataset.userId));
    if (!u) return;
    if (btn.dataset.action === "activate") {
      cambiarEstadoUsuario(u.id, 1);
    } else {
      userToDeactivate = u;
      $("targetUser").textContent = u.nombre;
      $("deactivateDialog").showModal();
    }
  };

  $("confirmDeactivate").onclick = () => {
    if (userToDeactivate) cambiarEstadoUsuario(userToDeactivate.id, 0);
    $("deactivateDialog").close();
  };

  async function cambiarEstadoUsuario(id, estado) {
    await apiFetch(`${API}/usuarios/${id}/estado`, { method: "PUT", body: JSON.stringify({ estado }) });
    cargarUsuarios();
  }

  // --- Roles y Permisos ---
  async function cargarRoles() {
    try {
      const res = await apiFetch(`${API}/roles`);
      const data = await res.json();
      if (data.success) {
        listaRoles = data.roles;
        renderizarRoles();
        renderizarAsignacionRoles();
      }
    } catch {}
  }

  function renderizarRoles() {
    $("rolesTableBody").innerHTML = listaRoles.map(r => `
      <tr>
        <td><span class="code-badge">${esc(r.codigo)}</span></td>
        <td><strong>${esc(r.nombre)}</strong></td>
        <td>${esc(r.descripcion || "-")}</td>
        <td><span class="status-badge ${r.activo ? "active" : "inactive"}">${r.activo ? "Activo" : "Inactivo"}</span></td>
        <td style="text-align:right;">
          <button class="btn-icon" data-edit-role="${r.id}">Editar</button>
          ${r.codigo !== "ROLE_ADMIN" ? `<button class="btn-icon" data-toggle-role="${r.id}">${r.activo ? "Desactivar" : "Activar"}</button>` : ""}
        </td>
      </tr>
    `).join("");
  }

  function renderizarAsignacionRoles() {
    if (!$("usersRolesTableBody") || !listaRoles.length) return;
    $("usersRolesTableBody").innerHTML = listaUsuarios.map(u => {
      const opts = listaRoles.map(r => `<option value="${r.id}" ${u.rol_id === r.id ? "selected" : ""} ${!r.activo ? "disabled" : ""}>${esc(r.nombre)}</option>`).join("");
      return `
        <tr>
          <td><strong>${esc(u.nombre)}</strong></td>
          <td>${esc(u.email)}</td>
          <td><select class="role-select" id="select-rol-${u.id}">${opts}</select></td>
          <td style="text-align:right;"><button class="btn-sm-save" data-assign-user="${u.id}">Guardar</button></td>
        </tr>
      `;
    }).join("");
  }

  $("btnNewRole").onclick = () => {
    editingRoleId = null;
    $("roleForm").reset();
    $("roleCode").readOnly = false;
    $("modalTitle").textContent = "Nuevo Rol";
    $("roleModal").showModal();
  };

  $("rolesTableBody").onclick = async (e) => {
    const editBtn = e.target.closest("[data-edit-role]");
    const toggleBtn = e.target.closest("[data-toggle-role]");
    if (editBtn) {
      const rol = listaRoles.find(r => r.id === Number(editBtn.dataset.editRole));
      if (!rol) return;
      editingRoleId = rol.id;
      $("roleCode").value = rol.codigo;
      $("roleCode").readOnly = true;
      $("roleName").value = rol.nombre;
      $("roleDescription").value = rol.descripcion || "";
      $("modalTitle").textContent = "Editar Rol";
      $("roleModal").showModal();
    } else if (toggleBtn) {
      const rol = listaRoles.find(r => r.id === Number(toggleBtn.dataset.toggleRole));
      if (!rol) return;
      await apiFetch(`${API}/roles/${rol.id}`, { method: "PUT", body: JSON.stringify({ activo: rol.activo ? 0 : 1 }) });
      cargarRoles();
    }
  };

  $("usersRolesTableBody").onclick = async (e) => {
    const btn = e.target.closest("[data-assign-user]");
    if (!btn) return;
    const uid = btn.dataset.assignUser;
    const select = $(`select-rol-${uid}`);
    await apiFetch(`${API}/usuarios/${uid}/rol`, { method: "PUT", body: JSON.stringify({ rol_id: Number(select.value) }) });
    $("roleSuccess").hidden = false;
    $("roleSuccessText").textContent = "Rol asignado correctamente.";
    cargarUsuarios();
  };

  $("roleForm").onsubmit = async (e) => {
    e.preventDefault();
    const codigo = $("roleCode").value.trim(), nombre = $("roleName").value.trim(), descripcion = $("roleDescription").value.trim();
    const url = editingRoleId ? `${API}/roles/${editingRoleId}` : `${API}/roles`;
    const method = editingRoleId ? "PUT" : "POST";
    const res = await apiFetch(url, { method, body: JSON.stringify({ codigo, nombre, descripcion }) });
    const data = await res.json();
    if (data.success) {
      $("roleModal").close();
      $("roleSuccess").hidden = false;
      $("roleSuccessText").textContent = data.message;
      cargarRoles();
    } else alert(data.message);
  };

  // --- Cerrar Sesión ---
  $("logoutBtn").onclick = async () => {
    try { await apiFetch(`${API}/logout`, { method: "POST" }); } catch {}
    sessionStorage.removeItem("usuario");
    location.replace("index.html");
  };
});

