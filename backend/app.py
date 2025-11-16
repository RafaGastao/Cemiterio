import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
import os
import uuid
import logging
from logging.handlers import RotatingFileHandler
import json
import base64
from threading import Thread

from flask import Flask, jsonify, request, g, send_from_directory, Response
from flask_cors import CORS 

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

import jwt 
import datetime

# --- CONFIGURAÇÃO DE CRIPTOGRAFIA ---
# Carrega as chaves das variáveis de ambiente para persistência
server_private_key = None
server_public_key = None
try:
    private_key_pem = os.getenv('SERVER_PRIVATE_KEY_PEM')
    public_key_pem = os.getenv('SERVER_PUBLIC_KEY_PEM')
    if not private_key_pem or not public_key_pem:
        raise ValueError("As variáveis de ambiente das chaves RSA não foram definidas.")
    
    server_private_key = RSA.import_key(private_key_pem)
    server_public_key = public_key_pem.encode('utf-8') # Mantém em formato PEM para envio
    logging.info("Chaves RSA carregadas com sucesso das variáveis de ambiente.")
except Exception as e:
    logging.critical(f"ERRO CRÍTICO: Falha ao carregar as chaves RSA. Erro: {e}")

# Armazena as chaves públicas dos clientes em memória
client_public_keys = {}

# --- CONFIGURAÇÃO DE LOGGING ---
# Configura o logger para salvar em um arquivo
log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s')
log_file = 'app.log'
# Rotação de arquivos: 1MB por arquivo, mantém até 5 arquivos de backup
my_handler = RotatingFileHandler(log_file, maxBytes=1024*1024, backupCount=5)
my_handler.setFormatter(log_formatter)
my_handler.setLevel(logging.INFO)

# Ajuste para servir arquivos estáticos da pasta raiz do projeto
app = Flask(__name__, static_folder='..', static_url_path='/')
app.logger.addHandler(my_handler)
app.logger.setLevel(logging.INFO)



# Modificado para usar variável de ambiente para a URL do frontend e ser mais específico na rota
frontend_url = os.getenv('FRONTEND_URL', 'http://127.0.0.1:5500')
CORS(app, resources={r"/api/*": {"origins": [frontend_url, "http://localhost:5500", "https://cemiterio-0elv.onrender.com"]}})
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'muda_essa_chave_para_producao')


# --- HELPERS DE CRIPTOGRAFIA ---
def decrypt_request_payload(payload):
    """
    Decriptografa o payload da requisição que foi criptografado pelo cliente.
    Utiliza a chave privada do servidor para decriptografar a chave de sessão AES,
    e então usa a chave de sessão para decriptografar os dados.
    """
    try:
        # Decodifica os dados de Base64
        encrypted_key = base64.b64decode(payload['encrypted_key'])
        iv = base64.b64decode(payload['iv'])
        ciphertext = base64.b64decode(payload['data'])

        # Decriptografa a chave AES com a chave privada do servidor
        # Especifica SHA256 para corresponder ao frontend (Web Crypto API)
        cipher_rsa = PKCS1_OAEP.new(server_private_key, hashAlgo=SHA256)
        session_key = cipher_rsa.decrypt(encrypted_key)

        # Decriptografa os dados com a chave AES no modo CBC
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv=iv)
        decrypted_data = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
        
        return json.loads(decrypted_data.decode('utf-8'))
    except (ValueError, KeyError, TypeError) as e:
        app.logger.error(f"Payload decryption failed: {e}")
        return None

def encrypt_response_payload(data, user_id):
    """
    Criptografa os dados da resposta para enviar ao cliente.
    Utiliza a chave pública do cliente (armazenada em memória) para criptografar
    uma chave de sessão AES, e então criptografa os dados com essa chave.
    """
    try:
        client_pub_key_str = client_public_keys.get(user_id)
        if not client_pub_key_str:
            raise ValueError("Client public key not found for user.")

        client_public_key = RSA.import_key(client_pub_key_str)
        
        # Gera uma chave de sessão AES
        session_key = os.urandom(32) # Chave de 256 bits (32 bytes)
        iv = os.urandom(16) # IV de 16 bytes para CBC

        # Criptografa a chave de sessão com a chave pública do cliente
        # Especifica SHA256 para corresponder ao frontend
        cipher_rsa = PKCS1_OAEP.new(client_public_key, hashAlgo=SHA256)
        encrypted_key = cipher_rsa.encrypt(session_key)

        # Criptografa os dados com AES-CBC
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv=iv)
        data_bytes = json.dumps(data, default=str).encode('utf-8')
        padded_data = pad(data_bytes, AES.block_size)
        ciphertext = cipher_aes.encrypt(padded_data)

        # Codifica tudo em Base64 para transporte
        return {
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'data': base64.b64encode(ciphertext).decode('utf-8')
        }
    except Exception as e:
        app.logger.error(f"Response encryption failed: {e}")
        return None

# --- FIM HELPERS DE CRIPTOGRAFIA ---


def get_db_connection():
    """
    Estabelece e retorna uma conexão com o banco de dados PostgreSQL.
    Prioriza a variável de ambiente DATABASE_URL (usada pelo Render) e,
    como alternativa, usa as variáveis de ambiente individuais para desenvolvimento local.
    """
    try:
        # Usa a DATABASE_URL fornecida pelo Render, com fallback para variáveis locais
        db_url = os.getenv('DATABASE_URL')
        if not db_url:
            # Fallback para desenvolvimento local se DATABASE_URL não estiver definida
            db_url = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT', 5432)}/{os.getenv('DB_DATABASE')}"
        
        conn = psycopg2.connect(db_url, cursor_factory=RealDictCursor)
        return conn
    except psycopg2.Error as e:
        app.logger.error('DB connection error: %s', e)
        return None


# Helper: Generate password hash with salt
def generate_password_hash(password):
    """Gera um hash de senha seguro usando PBKDF2-SHA256 com um salt aleatório."""
    salt = os.urandom(16)  # Generate a 16-byte salt
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + ':' + hash_obj.hex()

# Helper: Verify password hash
def verify_password(password, stored_hash):
    """Verifica se uma senha corresponde a um hash armazenado."""
    try:
        salt, hash_value = stored_hash.split(':')
        salt = bytes.fromhex(salt)
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return hash_obj.hex() == hash_value
    except (ValueError, IndexError):
        # Lida com casos onde o split falha ou o hash não está no formato esperado.
        # Isso previne o crash da aplicação por senhas em formato antigo/inválido.
        return False

# Helper: Verifica se um token está na blacklist
def is_token_revoked(jti):
    """Verifica no banco de dados se o JTI (identificador único) de um token foi revogado (está na blacklist)."""
    conn = get_db_connection()
    if not conn:
        return True # Em caso de erro de DB, assume que o token é inválido
    cur = conn.cursor()
    cur.execute("SELECT EXISTS (SELECT 1 FROM token_blacklist WHERE jti = %s)", (jti,))
    revoked = cur.fetchone()['exists']
    cur.close()
    conn.close()
    return revoked

# Helper: Hash and salt sensitive data (e.g., CPF)
def hash_sensitive_data(data):
    """Gera um hash seguro para dados sensíveis (ex: CPF) usando PBKDF2-SHA256 com salt."""
    salt = os.urandom(16)  # Generate a 16-byte salt
    hash_obj = hashlib.pbkdf2_hmac('sha256', data.encode(), salt, 100000)
    return salt.hex() + ':' + hash_obj.hex()

# Middleware para autenticação e decriptografia
@app.before_request
def before_request_handler():
    """
    Middleware executado antes de cada requisição.
    1. Autentica o usuário com base no token JWT.
    2. Decriptografa o corpo da requisição para rotas protegidas.
    """
    # 1. Autenticação
    authenticate_user()
    
    # 2. Decriptografia do Payload
    # Ignora endpoints que não devem ser criptografados
    exempt_paths = ['/api/login', '/api/security/public-key', '/api/forgot-password', '/api/token/refresh']
    if request.path in exempt_paths or request.path.startswith('/api/reset-password'):
        return

    if request.method in ['POST', 'PUT'] and request.is_json:
        encrypted_payload = request.get_json(silent=True)
        if (encrypted_payload and 'encrypted_key' in encrypted_payload):
            decrypted_payload = decrypt_request_payload(encrypted_payload)
            if decrypted_payload is None:
                # Retorna um erro explícito se a decriptografia falhar
                return jsonify({'error': 'Falha na decriptografia do payload'}), 400
            # Substitui o json da requisição pelo payload decriptografado
            request.json_decrypted = decrypted_payload
        else:
            # Se a criptografia é esperada mas não veio, pode ser um erro ou ataque
            app.logger.warning(f"Unencrypted payload received for protected route {request.path}")


# Middleware para autenticação e obtenção do usuário atual
# @app.before_request # Esta função foi movida para 'before_request_handler'
def authenticate_user():
    """
    Verifica o token de autorização no cabeçalho da requisição,
    decodifica-o e define g.current_user com os dados do usuário logado.
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        g.current_user = None
        return
    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        # Verifica se o token está na blacklist
        jti = decoded.get('jti')
        if not jti or is_token_revoked(jti):
            g.current_user = None
            return

        user_id = decoded.get('user_id')
        conn = get_db_connection()
        if not conn:  # <-- ADICIONAR ESTA VERIFICAÇÃO
            g.current_user = None
            return

        cur = conn.cursor()
        cur.execute('SELECT id, name, username, email, role FROM usuarios WHERE id = %s', (user_id,))
        user = cur.fetchone()
        if user:
            g.current_user = user # Já é um dicionário
        else:
            g.current_user = None
        cur.close()
        conn.close()
        app.logger.info(f"Authenticated user: {g.current_user}")
    except Exception as e:
        app.logger.error(f"Authentication error: {e}")
        g.current_user = None

# --- Rota para servir o frontend ---
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    """
    Serve os arquivos estáticos do frontend (HTML, CSS, JS).
    Se o caminho não for encontrado, serve o index.html para permitir o roteamento do lado do cliente (SPA).
    """
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    # Ignora as rotas da API para não entrar em conflito
    elif not path.startswith('api/'):
        return send_from_directory(app.static_folder, 'index.html')
    else:
        # Deixa o Flask tratar a rota da API que não foi encontrada
        return "Not Found", 404

# --- NEW: API Root Status Route ---
@app.route('/api', methods=['GET'])
def api_root():
    """Retorna uma mensagem de status e versão para a raiz da API."""
    return jsonify({
        'status': 'API is running',
        'version': '1.0',
        'available_routes': ['/api/login', '/api/usuarios', '/api/setores', '/api/falecidos', '/api/catalogo', '/api/carrinho', '/api/pedidos', '/api/financeiro']
    })

# --- NEW: Security Endpoints ---
@app.route('/api/security/public-key', methods=['GET'])
def get_server_public_key():
    """Fornece a chave pública RSA do servidor para que os clientes possam criptografar dados."""
    if not server_public_key:
        return jsonify({'error': 'Chave pública do servidor não disponível'}), 503
    return jsonify({'public_key': server_public_key.decode('utf-8')})

@app.route('/api/security/register-key', methods=['POST'])
def register_client_key():
    """
    Registra a chave pública de um cliente autenticado.
    A chave é armazenada em memória para criptografar respostas para esse cliente.
    """
    if not g.current_user:
        return jsonify({'error': 'Authentication required'}), 401
    
    data = request.get_json()
    public_key = data.get('public_key')
    if not public_key:
        return jsonify({'error': 'Public key is required'}), 400
        
    user_id = g.current_user['id']
    client_public_keys[user_id] = public_key
    app.logger.info(f"Registered public key for user_id {user_id}")
    
    return jsonify({'message': 'Key registered successfully'}), 200

# --- NEW: Password Recovery Routes ---
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    """
    Inicia o processo de recuperação de senha.
    Verifica se o e-mail e o nome de usuário correspondem a uma conta existente.
    Se sim, gera um token de uso único e o retorna ao cliente.
    """
    data = request.get_json()
    email = data.get('email')
    username = data.get('username') # Novo campo
    if not email or not username:
        return jsonify({'error': 'Email e nome de usuário são obrigatórios'}), 400

    conn = get_db_connection()
    if not conn: return jsonify({'error': 'Falha na conexão com o banco de dados'}), 500
    cur = conn.cursor()
    
    # Valida se o email e o usuário correspondem a uma conta existente
    cur.execute("SELECT id, name FROM usuarios WHERE email = %s AND username = %s", (email, username))
    user = cur.fetchone()

    if user:
        token = str(uuid.uuid4())
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=10) # Token de curta duração
        
        cur.execute(
            "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (%s, %s, %s)",
            (user['id'], token, expires_at)
        )
        conn.commit()
        cur.close()
        conn.close()
        # Retorna o token para o frontend
        return jsonify({'token': token}), 200
    else:
        cur.close()
        conn.close()
        # Resposta de erro se a combinação não for encontrada
        return jsonify({'error': 'Usuário ou email inválido'}), 404

@app.route('/api/reset-password/<token>', methods=['POST'])
def reset_password(token):
    """
    Redefine a senha do usuário usando um token de recuperação válido.
    Verifica se o token existe e não expirou, então atualiza a senha do usuário.
    """
    data = request.get_json()
    new_password = data.get('password')
    if not new_password:
        return jsonify({'error': 'New password is required'}), 400

    conn = get_db_connection()
    if not conn: return jsonify({'error': 'DB connection error'}), 500
    cur = conn.cursor()

    cur.execute(
        "SELECT user_id, expires_at FROM password_reset_tokens WHERE token = %s", (token,)
    )
    reset_req = cur.fetchone()

    if not reset_req or reset_req['expires_at'].replace(tzinfo=None) < datetime.datetime.utcnow():
        cur.close()
        conn.close()
        return jsonify({'error': 'Token inválido ou expirado'}), 400

    hashed_password = generate_password_hash(new_password)
    cur.execute("UPDATE usuarios SET password = %s WHERE id = %s", (hashed_password, reset_req['user_id']))
    
    # Invalida o token de reset
    cur.execute("DELETE FROM password_reset_tokens WHERE token = %s", (token,))
    conn.commit()

    cur.close()
    conn.close()
    
    app.logger.info(f"Password reset successfully for user_id {reset_req['user_id']}")
    return jsonify({'message': 'Senha redefinida com sucesso.'}), 200


# --- NEW: Refresh Token Route ---
@app.route('/api/token/refresh', methods=['POST'])
def refresh_token():
    """
    Gera um novo Access Token a partir de um Refresh Token válido.
    Permite que o usuário mantenha a sessão ativa sem precisar fazer login novamente.
    """
    data = request.get_json()
    refresh_token = data.get('refresh_token')
    if not refresh_token:
        return jsonify({'error': 'Refresh token is required'}), 400

    try:
        decoded = jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        # Verifica se é um refresh token e se não está na blacklist
        if decoded.get('type') != 'refresh' or is_token_revoked(decoded.get('jti')):
            return jsonify({'error': 'Invalid or revoked refresh token'}), 401

        user_id = decoded.get('user_id')
        access_token = jwt.encode(
            {
                'user_id': user_id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
                'jti': str(uuid.uuid4()),
                'type': 'access'
            },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        return jsonify({'access_token': access_token})
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Refresh token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid refresh token'}), 401

# --- NEW: Logout Route ---
@app.route('/api/logout', methods=['POST'])
def logout():
    """
    Invalida o Access Token do usuário adicionando seu JTI à blacklist.
    Isso impede que o token seja reutilizado após o logout.
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return jsonify({'message': 'No token provided'}), 200

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'DB connection error'}), 500
    
    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'], options={"verify_exp": False})
        jti = decoded.get('jti')
        if jti:
            cur = conn.cursor()
            cur.execute("INSERT INTO token_blacklist (jti) VALUES (%s) ON CONFLICT (jti) DO NOTHING", (jti,))
            conn.commit()
            cur.close()
        return jsonify({'message': 'Successfully logged out'}), 200
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 200 # Não retorna erro, apenas confirma que não há sessão válida
    finally:
        if conn:
            conn.close()

# --- Auth: login (simples) ---
@app.route('/api/login', methods=['POST'])
def login():
    """
    Autentica um usuário com nome de usuário e senha.
    Se as credenciais forem válidas, retorna um Access Token (curta duração)
    e um Refresh Token (longa duração), junto com os dados do usuário.
    """
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'db connection error'}), 500

    cur = conn.cursor()
    try:
        cur.execute('SELECT id, name, username, email, password, role FROM usuarios WHERE username = %s', (username,))
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'invalid credentials'}), 401

        user = row # Já é um dicionário
        stored_password = user['password']

        # Debugging log
        app.logger.info(f"Login attempt: username={username}")

        # Verify password hash
        if not verify_password(password, stored_password):
            app.logger.warning(f"Invalid password for user {username}")
            return jsonify({'error': 'invalid credentials'}), 401

        # Criar Access Token (curta duração)
        access_token = jwt.encode(
            {
                'user_id': user['id'], 
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15), # Duração de 15 minutos
                'jti': str(uuid.uuid4()),
                'type': 'access'
            },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        
        # Criar Refresh Token (longa duração)
        refresh_token = jwt.encode(
            {
                'user_id': user['id'], 
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7), # Duração de 7 dias
                'jti': str(uuid.uuid4()),
                'type': 'refresh'
            },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )

        # Retorna o usuário completo, exceto a senha
        user_data_to_return = {
            'id': user['id'], 
            'name': user['name'], 
            'username': user['username'],
            'email': user['email'],
            'role': user['role']
        }
        return jsonify({
            'access_token': access_token, 
            'refresh_token': refresh_token,
            'user': user_data_to_return
        })
    except Exception as e:
        app.logger.error(f"Error during login: {e}")
        return jsonify({'error': 'internal server error'}), 500
    finally:
        cur.close()
        conn.close()


# --- Usuarios CRUD (SEM AUTORIZAÇÃO NO POST) ---
@app.route('/api/usuarios', methods=['GET','POST'])
def usuarios_collection():
    """
    Endpoint para a coleção de usuários.
    GET: Lista todos os usuários (apenas para admins).
    POST: Cria um novo usuário (aberto para registro de novas contas).
    """
    conn = get_db_connection()
    if not conn: return jsonify({'error': 'DB connection error'}), 500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, name, username, email, role FROM usuarios')
        data = cur.fetchall()
        cur.close(); conn.close();
        return jsonify(data)
    else:
        payload = getattr(request, 'json_decrypted', request.json or {})
        hashed_password = generate_password_hash(payload.get('password'))  # Hash the password
        cur.execute('INSERT INTO usuarios (name, username, email, password, role) VALUES (%s,%s,%s,%s,%s) RETURNING id',
                    (payload.get('name'), payload.get('username'), payload.get('email'), hashed_password, payload.get('role','visitante')))
        uid = cur.fetchone()['id']
        conn.commit()
        cur.close(); conn.close();
        return jsonify({'id': uid}), 201

@app.route('/api/usuarios/<int:uid>', methods=['GET','PUT','DELETE'])
def usuarios_single(uid):
    """
    Endpoint para um usuário específico.
    GET: Obtém os detalhes de um usuário.
    PUT: Atualiza os dados de um usuário.
    DELETE: Remove um usuário.
    Requer permissão de admin ou que o usuário esteja modificando o próprio perfil.
    """
    conn = get_db_connection()
    if not conn: return jsonify({'error':'db'}), 500
    cur = conn.cursor()

    # --- VERIFICAÇÃO DE PERMISSÃO ---
    # O usuário deve ser admin OU estar modificando o próprio perfil
    is_admin = g.current_user and g.current_user.get('role') == 'admin'
    is_self = g.current_user and g.current_user.get('id') == uid

    if request.method in ['PUT', 'DELETE'] and not (is_admin or is_self):
        cur.close()
        conn.close()
        return jsonify({'error': 'Acesso negado'}), 403
    # --- FIM DA VERIFICAÇÃO ---

    if request.method == 'GET':
        cur.execute('SELECT id, name, username, email, role FROM usuarios WHERE id=%s', (uid,))
        user = cur.fetchone()
        if not user: cur.close(); conn.close(); return jsonify({'error': 'User not found'}), 404
        
        # Criptografa a resposta se o usuário estiver logado
        if g.current_user:
            encrypted_response = encrypt_response_payload(user, g.current_user['id'])
            if encrypted_response:
                cur.close(); conn.close(); return jsonify(encrypted_response)
        
        cur.close(); conn.close(); return jsonify(user)
    if request.method == 'PUT':
        p = getattr(request, 'json_decrypted', request.json or {})
        
        # Impede que usuários não-admin alterem seu próprio 'role'
        role = p.get('role')
        if not is_admin:
            cur.execute('SELECT role FROM usuarios WHERE id=%s', (uid,))
            user_role = cur.fetchone()
            if user_role:
                role = user_role['role'] # Mantém o role existente
        
        # Se o role ainda for nulo (não veio no payload e não é admin), busca o role atual para não anular.
        if role is None:
            cur.execute('SELECT role FROM usuarios WHERE id=%s', (uid,))
            user_role = cur.fetchone()
            if user_role:
                role = user_role['role']

        # Atualiza a senha apenas se uma nova for fornecida
        if p.get('password'):
            hashed_password = generate_password_hash(p.get('password'))
            cur.execute('UPDATE usuarios SET name=%s, username=%s, email=%s, password=%s, role=%s WHERE id=%s',
                        (p.get('name'), p.get('username'), p.get('email'), hashed_password, role, uid))
        else:
            cur.execute('UPDATE usuarios SET name=%s, username=%s, email=%s, role=%s WHERE id=%s',
                        (p.get('name'), p.get('username'), p.get('email'), role, uid))

        conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})
    if request.method == 'DELETE':
        cur.execute('DELETE FROM usuarios WHERE id=%s', (uid,)); conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})


# --- Setores CRUD ---
@app.route('/api/setores', methods=['GET','POST'])
def setores_collection():
    """
    Endpoint para a coleção de setores.
    GET: Lista todos os setores.
    POST: Cria um novo setor (requer admin).
    """
    conn = get_db_connection();
    if not conn: return jsonify([]), 500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, name, vagas FROM setores')
        data = cur.fetchall()
        cur.close(); conn.close();
        return jsonify(data)
    else:
        p = getattr(request, 'json_decrypted', request.json or {})
        cur.execute('INSERT INTO setores (name, vagas) VALUES (%s,%s) RETURNING id', (p.get('name'), p.get('vagas')))
        nid = cur.fetchone()['id']
        conn.commit();
        cur.close(); conn.close();
        return jsonify({'id': nid}), 201

@app.route('/api/setores/<int:sid>', methods=['GET','PUT','DELETE'])
def setores_single(sid):
    """
    Endpoint para um setor específico.
    GET: Obtém os detalhes de um setor.
    PUT: Atualiza um setor.
    DELETE: Remove um setor.
    Requer permissão de admin.
    """
    conn = get_db_connection();
    if not conn: return jsonify({'error':'db'}), 500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, name, vagas FROM setores WHERE id=%s', (sid,))
        row = cur.fetchone();
        if not row: cur.close(); conn.close(); return jsonify({'error': 'Setor not found'}), 404
        cur.close(); conn.close(); return jsonify(row)
    if request.method == 'PUT':
        p = getattr(request, 'json_decrypted', request.json or {})
        cur.execute('UPDATE setores SET name=%s, vagas=%s WHERE id=%s', (p.get('name'), p.get('vagas'), sid))
        conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})
    if request.method == 'DELETE':
        cur.execute('DELETE FROM setores WHERE id=%s', (sid,)); conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})

@app.route('/api/setores/vagas', methods=['GET'])
def listar_vagas():
    """Lista todos os setores e, para cada um, o status de cada vaga (ocupada ou disponível)."""
    conn = get_db_connection()
    if not conn: return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT s.id AS setor_id, s.name AS setor, s.vagas AS total_vagas
            FROM setores s
        """)
        setores = cur.fetchall()

        for setor in setores:
            cur.execute("""
                SELECT f.vaga
                FROM falecidos f
                WHERE f.setor = %s
            """, (setor['setor_id'],))
            ocupadas = [row['vaga'] for row in cur.fetchall()]
            setor['vagas'] = [{'numero': i + 1, 'ocupada': i + 1 in ocupadas} for i in range(setor['total_vagas'])]

        return jsonify(setores)
    except Exception as e:
        app.logger.error(f"Error listing vagas: {e}")
        return jsonify({'error': 'internal server error'}), 500
    finally:
        cur.close()
        conn.close()


# --- Falecidos CRUD ---
@app.route('/api/falecidos', methods=['GET', 'POST'])
def falecidos_collection():
    """
    Endpoint para a coleção de falecidos.
    GET: Lista falecidos. Admins veem todos, visitantes veem apenas os associados a eles.
    POST: Cria um novo registro de falecido (requer admin).
    """
    conn = get_db_connection()
    if not conn:
        return jsonify([]), 500
    cur = conn.cursor()

    if request.method == 'POST':
        try:
            payload = getattr(request, 'json_decrypted', request.json or {})
            cur.execute("""
                INSERT INTO falecidos (name, anonascimento, anomorte, setor, vaga)
                VALUES (%s, %s, %s, %s, %s) RETURNING id
            """, (
                payload.get('name'),
                payload.get('anoNascimento'), # Frontend envia com 'N' e 'M' maiúsculos
                payload.get('anoMorte'),
                payload.get('setor'),
                payload.get('vaga')
            ))
            new_id = cur.fetchone()['id']
            conn.commit()
            return jsonify({'id': new_id}), 201
        except Exception as e:
            app.logger.error(f"Error creating falecido: {e}")
            return jsonify({'error': str(e)}), 500
        finally:
            cur.close()
            conn.close()

    try:
        if (g.current_user and g.current_user['role'] == 'visitante'):
            # Visitantes só podem ver falecidos associados a eles
            cur.execute("""
                SELECT f.id, f.name, f.anonascimento, f.anomorte, s.name AS setor_nome, f.vaga,
                       COALESCE(STRING_AGG(DISTINCT p.nome, ', '), 'Nenhum') AS planos,
                       COALESCE(STRING_AGG(DISTINCT u.name, ', '), 'Nenhum') AS usuarios_associados
                FROM falecidos f
                INNER JOIN usuarios_falecidos uf ON f.id = uf.falecido_id
                LEFT JOIN usuarios u ON uf.user_id = u.id
                LEFT JOIN setores s ON f.setor = s.id
                LEFT JOIN falecidos_planos fp ON f.id = fp.falecido_id
                LEFT JOIN catalogo p ON fp.plano_id = p.id
                WHERE uf.user_id = %s
                GROUP BY f.id, s.name
            """, (g.current_user['id'],))
        else:
            # Administradores podem ver todos os falecidos
            cur.execute("""
                SELECT f.id, f.name, f.anonascimento, f.anomorte, s.name AS setor_nome, f.vaga,
                       COALESCE(STRING_AGG(DISTINCT p.nome, ', '), 'Nenhum') AS planos,
                       COALESCE(STRING_AGG(DISTINCT u.name, ', '), 'Nenhum') AS usuarios_associados
                FROM falecidos f
                LEFT JOIN usuarios_falecidos uf ON f.id = uf.falecido_id
                LEFT JOIN usuarios u ON uf.user_id = u.id
                LEFT JOIN setores s ON f.setor = s.id
                LEFT JOIN falecidos_planos fp ON f.id = fp.falecido_id
                LEFT JOIN catalogo p ON fp.plano_id = p.id
                GROUP BY f.id, s.name
            """)

        data = cur.fetchall()
        
        # Resposta para GET não será mais criptografada para simplificar
        return jsonify(data)
    except Exception as e:
        app.logger.error(f"Error fetching falecidos: {e}")
        return jsonify({'error': 'internal server error'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/falecidos/<int:fid>', methods=['GET','PUT','DELETE'])
def falecidos_single(fid):
    """
    Endpoint para um registro de falecido específico.
    GET: Obtém detalhes de um falecido.
    PUT: Atualiza um falecido.
    DELETE: Remove um falecido.
    Requer permissão de admin.
    """
    conn = get_db_connection();
    if not conn: return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, name, anonascimento, anomorte, setor FROM falecidos WHERE id=%s', (fid,))
        row = cur.fetchone();
        if not row: cur.close(); conn.close(); return jsonify({'error': 'Falecido not found'}), 404
        cur.close(); conn.close(); return jsonify(row)
    if request.method == 'PUT':
        p = getattr(request, 'json_decrypted', request.json or {})
        cur.execute('UPDATE falecidos SET name=%s, anonascimento=%s, anomorte=%s, setor=%s WHERE id=%s',
                    (p.get('name'), p.get('anoNascimento'), p.get('anoMorte'), p.get('setor'), fid))
        conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})
    if request.method == 'DELETE':
        cur.execute('DELETE FROM falecidos WHERE id=%s', (fid,)); conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})

@app.route('/api/falecidos/<int:fid>/atribuir-vaga', methods=['PUT'])
def atribuir_vaga(fid):
    """Atribui ou atualiza a vaga de um registro de falecido existente."""
    conn = get_db_connection()
    if not conn: return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    try:
        payload = getattr(request, 'json_decrypted', request.json or {})
        vaga = payload.get('vaga')
        setor = payload.get('setor')

        if not vaga or not setor:
            return jsonify({'error': 'Vaga e setor são obrigatórios'}), 400

        # Verificar se a vaga já está ocupada
        cur.execute("""
            SELECT COUNT(*)::int FROM falecidos WHERE setor = %s AND vaga = %s
        """, (setor, vaga))
        if cur.fetchone()['count'] > 0:
            return jsonify({'error': 'Esta vaga já está ocupada'}), 409

        # Atualizar a vaga do falecido
        cur.execute("""
            UPDATE falecidos SET vaga = %s, setor = %s WHERE id = %s
        """, (vaga, setor, fid))
        conn.commit()
        return jsonify({'ok': True}), 200
    except Exception as e:
        app.logger.error(f"Error assigning vaga: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# --- Associar falecidos a usuários ---
@app.route('/api/falecidos/<int:fid>/associar', methods=['POST'])
def associar_falecido(fid):
    """Cria uma associação entre um falecido e um usuário (requer admin)."""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    try:
        payload = getattr(request, 'json_decrypted', request.json or {})
        user_id = payload.get('user_id')

        if not user_id:
            return jsonify({'error': 'user_id é obrigatório'}), 400

        # Verificar se o falecido existe
        cur.execute('SELECT id FROM falecidos WHERE id = %s', (fid,))
        if not cur.fetchone():
            return jsonify({'error': 'Falecido não encontrado'}), 404

        # Verificar se a associação já existe
        cur.execute('SELECT COUNT(*)::int FROM usuarios_falecidos WHERE user_id = %s AND falecido_id = %s', (user_id, fid))
        if cur.fetchone()['count'] > 0:
            return jsonify({'error': 'Associação já existe'}), 409

        # Criar a associação
        cur.execute('INSERT INTO usuarios_falecidos (user_id, falecido_id) VALUES (%s, %s)', (user_id, fid))
        conn.commit()
        return jsonify({'ok': True}), 201
    except Exception as e:
        app.logger.error(f"Error associating falecido: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# --- Listar falecidos associados a um usuário ---
@app.route('/api/usuarios/<int:user_id>/falecidos', methods=['GET'])
def listar_falecidos_usuario(user_id):
    """Lista todos os falecidos associados a um ID de usuário específico."""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT f.id, f.name, f.anoNascimento, f.anoMorte, f.setor, f.vaga
            FROM falecidos f
            INNER JOIN usuarios_falecidos uf ON f.id = uf.falecido_id
            WHERE uf.user_id = %s
        """, (user_id,))
        falecidos = cur.fetchall()
        return jsonify(falecidos)
    except Exception as e:
        app.logger.error(f"Error listing falecidos for user: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# --- Associar falecidos a planos ---
@app.route('/api/falecidos/<int:fid>/associar-plano', methods=['POST'])
def associar_plano(fid):
    """Cria uma associação entre um falecido e um plano/produto do catálogo (requer admin)."""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    try:
        payload = getattr(request, 'json_decrypted', request.json or {})
        plano_id = payload.get('plano_id')

        if not plano_id:
            return jsonify({'error': 'plano_id é obrigatório'}), 400

        # Verificar se o falecido existe
        cur.execute('SELECT id FROM falecidos WHERE id = %s', (fid,))
        if not cur.fetchone():
            return jsonify({'error': 'Falecido não encontrado'}), 404

        # Verificar se o plano existe
        cur.execute('SELECT id FROM catalogo WHERE id = %s', (plano_id,))
        if not cur.fetchone():
            return jsonify({'error': 'Plano não encontrado'}), 404

        # Criar a associação
        cur.execute('INSERT INTO falecidos_planos (falecido_id, plano_id) VALUES (%s, %s)', (fid, plano_id))
        conn.commit()
        return jsonify({'ok': True}), 201
    except Exception as e:
        app.logger.error(f"Error associating plano: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/falecidos/<int:fid>/planos', methods=['GET'])
def listar_planos_falecido(fid):
    """Lista todos os planos/produtos associados a um falecido específico."""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT c.id, c.nome, c.descricao, c.preco
            FROM catalogo c
            INNER JOIN falecidos_planos fp ON c.id = fp.plano_id
            WHERE fp.falecido_id = %s
        """, (fid,))
        planos = cur.fetchall()
        return jsonify(planos)
    except Exception as e:
        app.logger.error(f"Error listing planos for falecido: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()


# --- Catálogo ---
@app.route('/api/catalogo', methods=['GET','POST'])
def catalogo_collection():
    """
    Endpoint para o catálogo de produtos/serviços.
    GET: Lista todos os itens do catálogo.
    POST: Adiciona um novo item ao catálogo (requer admin).
    """
    conn = get_db_connection();
    if not conn: return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, nome, descricao, preco FROM catalogo')
        data = cur.fetchall(); cur.close(); conn.close(); return jsonify(data)
    else:
        p = getattr(request, 'json_decrypted', request.json or {})
        cur.execute('INSERT INTO catalogo (nome, descricao, preco) VALUES (%s,%s,%s) RETURNING id', (p.get('nome'), p.get('descricao'), p.get('preco')))
        nid = cur.fetchone()['id']
        conn.commit(); cur.close(); conn.close(); return jsonify({'id': nid}), 201


# --- Carrinho (persistência de itens antes do pedido) ---
@app.route('/api/carrinho', methods=['GET','POST','DELETE'])
def carrinho_collection():
    """
    Endpoint para o carrinho de compras.
    GET: Lista itens no carrinho de um usuário.
    POST: Adiciona um item ao carrinho.
    DELETE: Limpa todos os itens do carrinho de um usuário.
    """
    conn = get_db_connection();
    if not conn: return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    if request.method == 'GET':
        user_id = request.args.get('user_id')
        if user_id:
            cur.execute('SELECT id, user_id, produto_id, quantidade FROM carrinho WHERE user_id=%s', (user_id,))
        else:
            cur.execute('SELECT id, user_id, produto_id, quantidade FROM carrinho')
        data = cur.fetchall(); cur.close(); conn.close(); return jsonify(data)
    if request.method == 'POST':
        p = getattr(request, 'json_decrypted', request.json or {})
        # espera: produto_id, quantidade, user_id (pode ser null)
        cur.execute('INSERT INTO carrinho (user_id, produto_id, quantidade) VALUES (%s,%s,%s) RETURNING id', (p.get('user_id'), p.get('produto_id'), p.get('quantidade')))
        nid = cur.fetchone()['id']
        conn.commit(); cur.close(); conn.close(); return jsonify({'id': nid}), 201
    if request.method == 'DELETE':
        # permitir deleção por user_id query param (limpar carrinho) ou corpo ?user_id=
        user_id = request.args.get('user_id')
        if user_id:
            cur.execute('DELETE FROM carrinho WHERE user_id=%s', (user_id,)); conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})
        else:
            cur.execute('DELETE FROM carrinho'); conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})


@app.route('/api/carrinho/<int:item_id>', methods=['GET','PUT','DELETE'])
def carrinho_item(item_id):
    """
    Endpoint para um item específico no carrinho.
    GET: Obtém detalhes de um item.
    PUT: Atualiza a quantidade de um item.
    DELETE: Remove um item do carrinho.
    """
    conn = get_db_connection();
    if not conn: return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, user_id, produto_id, quantidade FROM carrinho WHERE id=%s', (item_id,))
        row = cur.fetchone();
        if not row: cur.close(); conn.close(); return jsonify({'error': 'Item not found'}), 404
        cur.close(); conn.close(); return jsonify(row)
    if request.method == 'PUT':
        p = getattr(request, 'json_decrypted', request.json or {})
        cur.execute('UPDATE carrinho SET quantidade=%s WHERE id=%s', (p.get('quantidade'), item_id))
        conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})
    if request.method == 'DELETE':
        cur.execute('DELETE FROM carrinho WHERE id=%s', (item_id,)); conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})


# --- Pedidos (checkout) ---
@app.route('/api/pedidos', methods=['GET', 'POST'])
def pedidos_collection():
    """
    Endpoint para a coleção de pedidos.
    GET: Lista pedidos. Admins veem todos, usuários veem apenas os seus.
    POST: Cria um novo pedido a partir do checkout.
    """
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    
    if request.method == 'POST':
        p = getattr(request, 'json_decrypted', request.json or {})
        try:
            # Hash and salt the CPF
            hashed_cpf = hash_sensitive_data(p.get('cpf'))

            # Insert the order with default status 'Pendente'
            cur.execute(
                'INSERT INTO pedidos (user_id, nome, cpf, email, telefone, forma_pagamento, total, created_at, status) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id',
                (p.get('user_id'), p.get('nome'), hashed_cpf, p.get('email'), p.get('telefone'), p.get('forma_pagamento'), p.get('total'), datetime.datetime.utcnow(), 'Pendente')
            )
            pid = cur.fetchone()['id']

            # Insert order items
            for it in p.get('itens', []):
                cur.execute(
                    'INSERT INTO pedido_itens (pedido_id, produto_id, quantidade, preco) VALUES (%s,%s,%s,%s)',
                    (pid, it.get('produto_id'), it.get('quantidade'), it.get('preco'))
                )
            conn.commit()
            return jsonify({'id': pid}), 201
        except Exception as e:
            app.logger.error(f"Error creating order: {e}")
            return jsonify({'error': 'internal server error'}), 500
        finally:
            cur.close()
            conn.close()
    
    if request.method == 'GET':
        """Lista pedidos realizados. Admins veem todos os pedidos, usuários veem apenas os próprios."""
        try:
            if (g.current_user and g.current_user['role'] == 'admin'):
                # Admins podem ver todos os pedidos
                cur.execute("""
                    SELECT p.id, p.user_id, u.name AS usuario, p.nome, p.email, p.telefone, p.forma_pagamento, p.total, p.status, p.created_at
                    FROM pedidos p
                    LEFT JOIN usuarios u ON p.user_id = u.id
                """)
            elif (g.current_user):
                # Usuários comuns veem apenas os próprios pedidos
                cur.execute("""
                    SELECT p.id, p.user_id, u.name AS usuario, p.nome, p.email, p.telefone, p.forma_pagamento, p.total, p.status, p.created_at
                    FROM pedidos p
                    LEFT JOIN usuarios u ON p.user_id = u.id
                    WHERE p.user_id = %s
                """, (g.current_user['id'],))
            else:
                # Se não estiver logado, retorna lista vazia ou erro
                cur.close()
                conn.close()
                return jsonify([]), 200

            pedidos = cur.fetchall()
            
            # Resposta para GET não será mais criptografada
            return jsonify(pedidos)
        except Exception as e:
            app.logger.error(f"Error fetching pedidos: {e}")
            return jsonify({'error': 'internal server error'}), 500
        finally:
            cur.close()
            conn.close()

@app.route('/api/pedidos/<int:pedido_id>/aprovar', methods=['PUT'])
def aprovar_pedido(pedido_id):
    """Permite que um administrador aprove ou rejeite um pedido alterando seu status."""
    if not g.current_user or g.current_user['role'] != 'admin':
        return jsonify({'error': 'Acesso negado'}), 403

    conn = get_db_connection()
    if not conn: return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    try:
        # Lê o JSON diretamente, pois a requisição não será mais criptografada
        payload = request.get_json()
        if not payload:
            return jsonify({'error': 'Payload da requisição inválido ou ausente.'}), 400
            
        novo_status = payload.get('status')  # Espera 'Aprovado' ou 'Rejeitado'
        if not novo_status:
            return jsonify({'error': 'O campo "status" é obrigatório.'}), 400

        cur.execute('UPDATE pedidos SET status = %s WHERE id = %s', (novo_status, pedido_id))
        conn.commit()
        return jsonify({'message': 'Status do pedido atualizado com sucesso'}), 200
    except Exception as e:
        app.logger.error(f"Error updating approval status: {e}")
        return jsonify({'error': 'internal server error'}), 500
    finally:
        cur.close()
        conn.close()


# --- Financeiro ---
@app.route('/api/financeiro', methods=['GET','POST'])
def financeiro_collection():
    """
    Endpoint para a coleção de registros financeiros.
    GET: Lista todos os registros (requer admin).
    POST: Cria um novo registro (receita ou despesa) (requer admin).
    """
    conn = get_db_connection()
    if not conn: return jsonify([]), 500
    cur = conn.cursor()
    
    if request.method == 'GET':
        try:
            cur.execute('SELECT id, tipo, descricao, valor, data, status FROM financeiro')
            data = cur.fetchall()
            return jsonify(data)
        except Exception as e:
            app.logger.error(f"Erro ao buscar registros financeiros: {e}")
            return jsonify({'error': 'Erro interno ao buscar dados.'}), 500
        finally:
            cur.close()
            conn.close()
    
    if request.method == 'POST':
        p = getattr(request, 'json_decrypted', request.json or {})
        # --- Validação dos dados de entrada ---
        tipo_str = p.get('tipo')
        valor_str = p.get('valor')
        data_str = p.get('data')

        if not tipo_str or valor_str is None or not data_str:
            return jsonify({'error': 'Os campos "tipo", "valor" e "data" são obrigatórios.'}), 400
        
        # Mapeamento do tipo de transação
        tipo_map = {'receita': 'Entrada', 'despesa': 'Saída'}
        tipo_db = tipo_map.get(tipo_str.lower())
        if not tipo_db:
            return jsonify({'error': 'O campo "tipo" deve ser "receita" ou "despesa".'}), 400

        try:
            valor = float(valor_str)
            # Converte a string de data (YYYY-MM-DD) para um objeto date
            data = datetime.datetime.strptime(data_str, '%Y-%m-%d').date()
        except (ValueError, TypeError, AttributeError):
            return jsonify({'error': 'O campo "valor" deve ser um número e "data" deve estar no formato AAAA-MM-DD.'}), 400
        # --- Fim da validação ---

        try:
            cur.execute(
                'INSERT INTO financeiro (tipo, descricao, valor, data) VALUES (%s, %s, %s, %s) RETURNING id',
                (tipo_db, p.get('descricao'), valor, data)
            )
            nid = cur.fetchone()['id']
            conn.commit()
            return jsonify({'id': nid}), 201
        except Exception as e:
            conn.rollback()  # Desfaz a transação em caso de erro
            app.logger.error(f"Erro ao criar registro financeiro: {e}")  # Log do erro no console do backend
            return jsonify({'error': 'Erro interno ao salvar no banco de dados. Verifique o formato dos dados e os nomes das colunas.'}), 500
        finally:
            cur.close()
            conn.close()

@app.route('/api/financeiro/<int:fid>', methods=['GET','PUT','DELETE'])
def financeiro_single(fid):
    """
    Endpoint para um registro financeiro específico.
    GET: Obtém detalhes de um registro.
    PUT: Atualiza um registro.
    DELETE: Remove um registro.
    Requer permissão de admin.
    """
    conn = get_db_connection();
    if not conn: return jsonify({'error':'db'}), 500
    cur = conn.cursor()
    try:
        if request.method == 'GET':
            cur.execute('SELECT id, tipo, descricao, valor, data, status FROM financeiro WHERE id=%s', (fid,))
            row = cur.fetchone();
            if not row: return jsonify({}),404
            return jsonify(row)
        
        if request.method == 'PUT':
            # Lê o JSON diretamente, pois a requisição não será mais criptografada
            p = request.get_json()
            if not p:
                return jsonify({'error': 'Payload da requisição inválido ou ausente.'}), 400

            # --- Validação dos dados de entrada ---
            tipo_str = p.get('tipo')
            valor_str = p.get('valor')
            data_str = p.get('data')
            status_str = p.get('status') # Adicionado para ler o status

            if not tipo_str or valor_str is None or not data_str:
                return jsonify({'error': 'Os campos "tipo", "valor" e "data" são obrigatórios.'}), 400
            
            # Mapeamento do tipo de transação
            tipo_map = {'receita': 'Entrada', 'despesa': 'Saída'}
            tipo_db = tipo_map.get(tipo_str.lower())
            if not tipo_db:
                return jsonify({'error': 'O campo "tipo" deve ser "receita" ou "despesa".'}), 400

            try:
                valor = float(valor_str)
                # Converte a string de data (YYYY-MM-DD) para um objeto date
                data = datetime.datetime.strptime(data_str, '%Y-%m-%d').date()
            except (ValueError, TypeError, AttributeError):
                return jsonify({'error': 'O campo "valor" deve ser um número e "data" deve estar no formato AAAA-MM-DD.'}), 400
            # --- Fim da validação ---

            cur.execute('UPDATE financeiro SET tipo=%s, descricao=%s, valor=%s, data=%s, status=%s WHERE id=%s', 
                        (tipo_db, p.get('descricao'), valor, data, status_str, fid))
            conn.commit()
            return jsonify({'ok':True})

        if request.method == 'DELETE':
            cur.execute('DELETE FROM financeiro WHERE id=%s', (fid,)); 
            conn.commit()
            return jsonify({'ok':True})
            
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Erro na operação com financeiro ID {fid}: {e}")
        return jsonify({'error': 'Erro interno no servidor'}), 500
    finally:
        cur.close()
        conn.close()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)