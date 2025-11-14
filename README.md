# Cemitério Online - Sistema de Gestão

Este é um sistema de gestão completo para cemitérios, desenvolvido como uma Single Page Application (SPA). A aplicação conta com um frontend estático (HTML, CSS, JavaScript) e um backend RESTful em Python (Flask) que se comunica com um banco de dados PostgreSQL.

## Funcionalidades

- **Autenticação de Usuários**: Sistema de login com tokens JWT e níveis de acesso (Administrador, Visitante).
- **Gestão de Usuários**: CRUD completo para usuários (disponível para administradores).
- **Gestão de Setores e Vagas**: Cadastro de setores e visualização de vagas disponíveis/ocupadas.
- **Gestão de Falecidos**: Registro de informações de falecidos e associação a setores/vagas.
- **Associação de Dados**: Permite associar falecidos a usuários responsáveis.
- **Catálogo de Produtos/Serviços**: Exibição de itens disponíveis para compra.
- **Carrinho de Compras e Pedidos**: Funcionalidade de e-commerce para aquisição de produtos/serviços.
- **Módulo Financeiro**: Controle de receitas e despesas.

## Estrutura do Projeto

```
/
├── backend/              # Contém a aplicação Flask (API)
│   ├── app.py            # Arquivo principal da API
│   ├── schema.sql        # Script de criação do banco de dados PostgreSQL
│   ├── requirements.txt  # Dependências Python
│   └── ...
├── index.html            # Ponto de entrada do frontend
├── app.js                # Lógica principal do frontend (SPA)
├── styles.css            # Estilos da aplicação
├── termos-de-uso.html
└── politica-de-privacidade.html
```

## Pré-requisitos

- **Python 3.10+**
- **PostgreSQL**
- **Visual Studio Code** (recomendado) com a extensão **Live Server**.

---

## Configuração do Ambiente

### 1. Banco de Dados (PostgreSQL)

1.  Instale o PostgreSQL em sua máquina.
2.  Crie um novo banco de dados. Ex: `cemiterio_db`.
3.  Execute o script `backend/schema.sql` para criar todas as tabelas necessárias.

    ```sql
    -- Exemplo de como executar via psql
    psql -U seu_usuario -d cemiterio_db -f backend/schema.sql
    ```

### 2. Backend (Python/Flask)

1.  Navegue até a pasta `backend`:
    ```bash
    cd backend
    ```

2.  Crie e ative um ambiente virtual:
    ```bash
    # Windows
    python -m venv .venv
    .\.venv\Scripts\activate

    # macOS/Linux
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  Instale as dependências:
    ```bash
    pip install -r requirements.txt
    ```

4.  Configure as variáveis de ambiente para conexão com o banco de dados. Crie um arquivo `.env` na pasta `backend` com o seguinte conteúdo (substitua com suas credenciais):
    ```
    DB_HOST=localhost
    DB_DATABASE=cemiterio_db
    DB_USER=seu_usuario_postgres
    DB_PASSWORD=sua_senha_postgres
    DB_PORT=5432
    SECRET_KEY=uma-chave-secreta-forte-e-aleatoria
    FRONTEND_URL=http://127.0.0.1:5500
    ```

5.  Inicie o servidor backend:
    ```bash
    python app.py
    ```
    O servidor estará rodando em `http://127.0.0.1:5000`.

### 3. Frontend (HTML/CSS/JS)

O frontend é composto por arquivos estáticos. Para evitar problemas de CORS durante o desenvolvimento, é necessário servi-los a partir de um servidor web local.

1.  Abra a pasta raiz do projeto no Visual Studio Code.
2.  Instale a extensão **Live Server**.
3.  Clique com o botão direito no arquivo `index.html` e selecione "Open with Live Server".
4.  Seu navegador abrirá a aplicação em um endereço como `http://127.0.0.1:5500`.

A aplicação estará pronta para uso, conectando-se ao backend que você iniciou no passo anterior.

### Variáveis de Ambiente

Para que a aplicação funcione corretamente, especialmente em produção (ex: Render), você deve configurar as seguintes variáveis de ambiente:

#### Banco de Dados (PostgreSQL)
- `DB_HOST`: Endereço do servidor do banco de dados.
- `DB_USER`: Nome do usuário do banco.
- `DB_PASSWORD`: Senha do usuário do banco.
- `DB_DATABASE`: Nome do banco de dados.
- `DB_PORT`: Porta de conexão (geralmente `5432`).

#### Chave Secreta do Flask
- `SECRET_KEY`: Uma chave longa e aleatória para a segurança das sessões e tokens.

#### URL do Frontend
- `FRONTEND_URL`: A URL base do seu frontend (ex: `http://127.0.0.1:5500` para local ou a URL do seu site no Render).

## Deploy (Render)

- **Backend**: Faça o deploy da pasta `backend` como um "Web Service" no Render.
  - **Build Command**: `pip install -r requirements.txt`
  - **Start Command**: `gunicorn app:app`
  - Configure as variáveis de ambiente (DB, SECRET_KEY, etc.) na interface do Render.

- **Frontend**: Faça o deploy da pasta raiz como um "Static Site" no Render.
  - O Render servirá automaticamente o `index.html` e os outros arquivos estáticos.

---

## Detalhes Técnicos da API

### Autenticação

A autenticação é baseada em **JSON Web Tokens (JWT)**.
- O endpoint `POST /api/login` retorna um token de acesso ao receber credenciais válidas.
- Este token deve ser enviado em todas as requisições subsequentes no cabeçalho `Authorization` como `Bearer <token>`.
- As senhas dos usuários são armazenadas de forma segura no banco de dados usando hash com salt (PBKDF2-SHA256).

### Endpoints da API

- `GET /api`: Status da API.
- `POST /api/login`: Autenticação de usuário.

- **Usuários**:
  - `GET /api/usuarios`: Lista todos os usuários (admin).
  - `POST /api/usuarios`: Cria um novo usuário.
  - `GET /api/usuarios/<id>`: Obtém um usuário específico.
  - `PUT /api/usuarios/<id>`: Atualiza um usuário.
  - `DELETE /api/usuarios/<id>`: Deleta um usuário.

- **Setores**:
  - `GET /api/setores`: Lista todos os setores.
  - `POST /api/setores`: Cria um novo setor.
  - `GET /api/setores/vagas`: Lista vagas por setor.

- **Falecidos**:
  - `GET /api/falecidos`: Lista falecidos (filtrado por permissão).
  - `POST /api/falecidos`: Cria um novo registro de falecido.
  - `POST /api/falecidos/<id>/associar`: Associa um falecido a um usuário.
  - `PUT /api/falecidos/<id>/atribuir-vaga`: Atribui ou atualiza a vaga de um falecido.

- **Comercial**:
  - `GET /api/catalogo`: Lista produtos do catálogo.
  - `GET, POST, DELETE /api/carrinho`: Gerencia o carrinho de compras.
  - `GET, POST /api/pedidos`: Gerencia pedidos.
  - `PUT /api/pedidos/<id>/aprovar`: Aprova ou rejeita um pedido (admin).

- **Financeiro**:
  - `GET, POST /api/financeiro`: Gerencia registros financeiros.
  - `GET, PUT, DELETE /api/financeiro/<id>`: Gerencia um registro financeiro específico.

---

## Segurança

A aplicação implementa as seguintes medidas de segurança:

- **Hashing de Senhas com Salt**: As senhas dos usuários são protegidas usando o algoritmo `PBKDF2-SHA256` com um salt único para cada usuário, garantindo que não sejam armazenadas em texto plano.
- **Autenticação via JWT com Refresh Tokens**: O acesso é controlado por `Access Tokens` de curta duração e `Refresh Tokens` de longa duração, melhorando a segurança da sessão.
- **Revogação de Tokens (Logout Seguro)**: Tokens de acesso são invalidados no momento do logout através de uma blacklist, impedindo sua reutilização.
- **Recuperação de Senha**: O usuário informa seu e-mail e nome de usuário. Se a combinação for válida, um token de uso único e curta duração é gerado, permitindo a redefinição da senha.
- **Controle de Acesso Baseado em Função (RBAC)**: A API diferencia usuários `admin` e `visitante`, restringindo o acesso a endpoints críticos apenas para administradores.
- **Proteção contra CORS**: O backend limita as requisições para origens permitidas (a URL do frontend), prevenindo que sites maliciosos façam requisições à API em nome do usuário.
- **Hashing de Dados Sensíveis**: Dados como CPF são armazenados no banco de dados com hash e salt para maior proteção.
- **Logging de Eventos Críticos**: Ações importantes e erros no backend são registrados em arquivos de log para auditoria e monitoramento.
