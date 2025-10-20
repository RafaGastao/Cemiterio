-- schema.sql - Script para criar as tabelas do banco de dados 'cemiterio_db'

-- Criar banco de dados (se não existir)
CREATE DATABASE IF NOT EXISTS cemiterio_db;
USE cemiterio_db;

-- Tabela de usuários
CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL, -- Armazenar hash da senha
    role ENUM('admin', 'operador', 'visitante') DEFAULT 'visitante',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de setores
CREATE TABLE IF NOT EXISTS setores (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    vagas INT NOT NULL DEFAULT 0
);

-- Tabela de falecidos
CREATE TABLE IF NOT EXISTS falecidos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    anoNascimento INT NOT NULL,
    anoMorte INT NOT NULL,
    setor VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (setor) REFERENCES setores(name) ON DELETE CASCADE
);

-- Tabela de financeiro
CREATE TABLE IF NOT EXISTS financeiro (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tipo ENUM('Entrada', 'Saída') NOT NULL,
    descricao TEXT,
    valor DECIMAL(10,2) NOT NULL,
    data DATE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de catálogo (produtos/serviços)
CREATE TABLE IF NOT EXISTS catalogo (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(255) NOT NULL,
    descricao TEXT,
    preco DECIMAL(10,2) NOT NULL
);

-- Tabela de carrinho (para sessões de usuários)
CREATE TABLE IF NOT EXISTS carrinho (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT, -- Pode ser NULL para visitantes
    produto_id INT NOT NULL,
    quantidade INT NOT NULL DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
    FOREIGN KEY (produto_id) REFERENCES catalogo(id) ON DELETE CASCADE
);

-- Tabela de pedidos
CREATE TABLE IF NOT EXISTS pedidos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    nome VARCHAR(255),
    cpf VARCHAR(14),
    email VARCHAR(255),
    telefone VARCHAR(20),
    forma_pagamento VARCHAR(50),
    total DECIMAL(10,2) NOT NULL,
    status ENUM('pendente', 'pago', 'cancelado') DEFAULT 'pendente',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE SET NULL
);

-- Tabela de itens do pedido
CREATE TABLE IF NOT EXISTS pedido_itens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    pedido_id INT NOT NULL,
    produto_id INT NOT NULL,
    quantidade INT NOT NULL,
    preco DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (pedido_id) REFERENCES pedidos(id) ON DELETE CASCADE,
    FOREIGN KEY (produto_id) REFERENCES catalogo(id) ON DELETE CASCADE
);

-- Inserir dados iniciais
INSERT INTO usuarios (name, username, email, password, role) VALUES
('Admin', 'admin', 'admin@admin.com', '$2y$10$examplehash', 'admin'), -- Substitua por hash real
('Operador', 'oper', 'oper@admin.com', '$2y$10$examplehash', 'operador');

INSERT INTO setores (name, vagas) VALUES
('Setor A', 50),
('Setor B', 30);

INSERT INTO catalogo (nome, descricao, preco) VALUES
('Jazigo Simples', 'Jazigo para 1 pessoa', 2000.00),
('Jazigo Familiar', 'Jazigo para até 4 pessoas', 6000.00),
('Manutenção Anual', 'Limpeza e manutenção por 1 ano', 400.00),
('Arranjo de Flores', 'Arranjo de flores naturais', 120.00);