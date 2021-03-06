CREATE DATABASE IF NOT EXISTS DIGITALIZATE;
USE DIGITALIZATE;

-- Creación DDL
-- ------------------
-- Creación de Tabla Regiones
CREATE TABLE Years
(
	idYear TINYINT(2) NOT NULL AUTO_INCREMENT UNIQUE KEY,
	year YEAR NOT NULL,
    registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (idYear)
);
-- ------------------

-- Creación de Tabla Regiones
CREATE TABLE Regiones
(
	idRegion TINYINT(1) NOT NULL AUTO_INCREMENT UNIQUE KEY,
	nombre VARCHAR(45) NOT NULL UNIQUE KEY,
    registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (idRegion)
);
-- ------------------

-- Creación de Tabla Dimensiones
CREATE TABLE Dimensiones
(
	idDimension TINYINT(1) NOT NULL AUTO_INCREMENT UNIQUE KEY,
	nombre VARCHAR(45) NOT NULL,
    peso FLOAT NOT NULL,
    registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (idDimension)
);
-- ------------------

-- Creación de Tabla Fuentes
CREATE TABLE Fuentes
(
	idFuente TINYINT(2) NOT NULL AUTO_INCREMENT UNIQUE KEY,
	nombre VARCHAR(60) NOT NULL,
    descripcion TEXT NOT NULL,
    url TINYTEXT NOT NULL,
    version YEAR NOT NULL,
    registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (idFuente)
);
-- ------------------

-- Creación de Tabla Departamentos
CREATE TABLE Departamentos
(
	idDepartamento TINYINT(2) NOT NULL AUTO_INCREMENT UNIQUE KEY,
	nombre VARCHAR(45) NOT NULL UNIQUE KEY,
    idRegion TINYINT(1) NOT NULL,
    regionPerc FLOAT NOT NULL,
    registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (idDepartamento),
    CONSTRAINT PK_DEPARTAMENTO_REGION FOREIGN KEY (idRegion) REFERENCES Regiones(idRegion)
);
-- ------------------

-- Creación de Tabla Poblaciones
CREATE TABLE Poblaciones
(
	idPoblacion INT NOT NULL AUTO_INCREMENT UNIQUE KEY,
	idDepartamento TINYINT(2) NOT NULL,
    poblacion INT NOT NULL,
    idYear TINYINT(2) NOT NULL,
    registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (idPoblacion),
    CONSTRAINT PK_POBLACION_DEPARTAMENTO FOREIGN KEY (idDepartamento) REFERENCES Departamentos(idDepartamento),
    CONSTRAINT PK_POBLACION_YEAR FOREIGN KEY (idYear) REFERENCES Years(idYear)
);
-- ------------------

-- Creación de Tabla Categorias
CREATE TABLE Categorias
(
	idCategoria TINYINT(2) NOT NULL AUTO_INCREMENT UNIQUE KEY,
	nombre VARCHAR(45) NOT NULL UNIQUE KEY,
    idDimension TINYINT(1) NOT NULL,
    registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (idCategoria),
    CONSTRAINT PK_CATEGORIA_DIMENSION FOREIGN KEY (idDimension) REFERENCES Dimensiones(idDimension)
);
-- ------------------

-- Creación de Tabla Indicadores
CREATE TABLE Indicadores
(
	idIndicador TINYINT(3) NOT NULL AUTO_INCREMENT UNIQUE KEY,
    idCategoria TINYINT(2) NOT NULL,
    codigo CHAR(6) NOT NULL UNIQUE KEY,
	descripcion TEXT NOT NULL,
    peso FLOAT NOT NULL,
    minimo DECIMAL(16,13) NOT NULL,
    maximo DECIMAL(16,13) NOT NULL,
    idFuente TINYINT(2) NOT NULL,
    registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (idIndicador),
    CONSTRAINT PK_INDICADOR_CATEGORIA FOREIGN KEY (idCategoria) REFERENCES Categorias(idCategoria),
    CONSTRAINT PK_INDICADOR_FUENTE FOREIGN KEY (idFuente) REFERENCES Fuentes(idFuente)
);
-- ------------------

-- Creación de Tabla Valores
CREATE TABLE Valores
(
	idValores INT NOT NULL AUTO_INCREMENT UNIQUE KEY,
    idPoblacion INT NOT NULL,
    idIndicador TINYINT(3) NOT NULL,
	valor FLOAT(8,6) NOT NULL,
    registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (idValores),
    CONSTRAINT PK_VALOR_POBLACION FOREIGN KEY (idPoblacion) REFERENCES Poblaciones(idPoblacion),
    CONSTRAINT PK_VALOR_INDICADOR FOREIGN KEY (idIndicador) REFERENCES Indicadores(idIndicador)
);
-- ------------------
