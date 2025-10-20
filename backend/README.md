# Backend Python (Flask) para o projeto Cemiterio

Este backend fornece endpoints REST equivalentes ao `api.php`, mas implementados em Python/Flask.

Requisitos
- Python 3.10+
- MySQL (o banco `cemiterio_db` criado a partir de `schema.sql` do repositório)

Instalação (Windows CMD)
```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

Configuração
- Edite `backend/config.py` para ajustar credenciais do MySQL.

Rodando o servidor
```bash
cd backend
python app.py
```

Endpoints principais
- POST /api/login
- GET/POST /api/usuarios
- GET/POST /api/setores
- GET/POST /api/falecidos
- GET/POST /api/catalogo
- POST/GET /api/pedidos
- GET/POST/PUT/DELETE /api/financeiro

Notas
- Autenticação atualmente simples: tokens JWT são gerados no /api/login, sem refresh/blacklist.
- Senhas no banco ficam em texto puro na seed (veja schema.sql). Em produção use hashing.
