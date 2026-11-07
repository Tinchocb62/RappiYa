CREATE DATABASE IF NOT EXISTS rappiya;
USE rappiya;

CREATE TABLE IF NOT EXISTS roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    codigo VARCHAR(50) NOT NULL UNIQUE,
    nombre VARCHAR(100) NOT NULL UNIQUE,
    descripcion VARCHAR(255) NULL,
    activo TINYINT(1) DEFAULT 1,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO roles (codigo, nombre, descripcion, activo) VALUES
('ROLE_ADMIN', 'Administrador General', 'Acceso total a la configuración global y auditorías', 1),
('ROLE_REPARTIDOR', 'Repartidor (Rider)', 'Recepción y cambio de estado de entregas en tiempo real', 1),
('ROLE_COMERCIO', 'Gestor de Comercio', 'Gestión de productos, menús y pedidos del local', 1),
('ROLE_CLIENTE', 'Cliente', 'Búsqueda de productos, pedidos y seguimiento', 1)
ON DUPLICATE KEY UPDATE nombre=VALUES(nombre), descripcion=VALUES(descripcion);

CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    rol_id INT DEFAULT 4,
    direccion VARCHAR(255) DEFAULT NULL,
    telefono VARCHAR(50) DEFAULT NULL,
    estado TINYINT(1) DEFAULT 1,
    fecha_baja DATETIME DEFAULT NULL,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (rol_id) REFERENCES roles(id) ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS recuperacion_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    token VARCHAR(128) NOT NULL UNIQUE,
    expira_en DATETIME NOT NULL,
    usado TINYINT(1) DEFAULT 0,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auditoria (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    actor_id INT NOT NULL,
    fecha TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    accion VARCHAR(50) NOT NULL,
    entidad VARCHAR(50) NOT NULL,
    entidad_id INT NOT NULL,
    valor_anterior LONGTEXT NULL,
    valor_nuevo LONGTEXT NOT NULL,
    INDEX idx_auditoria_entidad (entidad, entidad_id),
    INDEX idx_auditoria_actor_fecha (actor_id, fecha),
    FOREIGN KEY (actor_id) REFERENCES usuarios(id) ON DELETE RESTRICT
);
