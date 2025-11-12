CREATE TABLE financeiro (
    id SERIAL PRIMARY KEY,
    tipo VARCHAR(50) NOT NULL, -- 'Entrada' ou 'Saída'
    descricao TEXT,
    valor DECIMAL(10, 2) NOT NULL,
    data DATE NOT NULL,
    status VARCHAR(50) DEFAULT 'Pendente' -- Ex: 'Pendente', 'Pago'
);

CREATE TABLE pedidos (
    id SERIAL PRIMARY KEY,
    user_id INT,
    nome VARCHAR(255) NOT NULL,
    cpf VARCHAR(255) NOT NULL, -- Armazenado como hash
    email VARCHAR(255) NOT NULL,
    telefone VARCHAR(50),
    forma_pagamento VARCHAR(50),
    total DECIMAL(10, 2) NOT NULL,
    status VARCHAR(50) DEFAULT 'Pendente', -- Ex: 'Pendente', 'Aprovado', 'Rejeitado'
    aprovado BOOLEAN DEFAULT FALSE, -- Mantido por compatibilidade, mas o 'status' é preferível
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE SET NULL
);

-- COMANDO DE ATUALIZAÇÃO (para quem já tem o banco criado):
-- Descomente e execute a linha abaixo se a tabela 'pedidos' já existe e você precisa adicionar a coluna 'status'.
-- ALTER TABLE pedidos ADD COLUMN status VARCHAR(50) DEFAULT 'Pendente';

-- Tabela para armazenar tokens de recuperação de senha
CREATE TABLE password_reset_tokens (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- Tabela para armazenar tokens JWT revogados (blacklist)
CREATE TABLE token_blacklist (
    id SERIAL PRIMARY KEY,
    jti VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
