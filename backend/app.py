import os
import logging
import base64
import json
import psycopg2
import hashlib
import jwt
import uuid
import datetime
from psycopg2.extras import RealDictCursor
from flask import Flask, jsonify, request, g
from flask_cors import CORS
from flask_mail import Mail, Message
from functools import wraps
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad

# --- CONFIGURAÇÃO INICIAL ---
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}}) # Permite todas as origens para a API

# Configuração do Flask-Mail (usando variáveis de ambiente)
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
mail = Mail(app)

# Configuração de Logging
logging.basicConfig(level=logging.INFO)

# Chave secreta para JWT (deve ser segura em produção)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'uma-chave-secreta-muito-forte-padrao')

# --- CONFIGURAÇÃO DE CRIPTOGRAFIA ---
server_private_key = None
server_public_key_pem = None
# Dicionário para armazenar chaves públicas dos clientes
client_public_keys = {}

try:
    private_key_pem = os.getenv('SERVER_PRIVATE_KEY_PEM')
    server_public_key_pem = os.getenv('SERVER_PUBLIC_KEY_PEM')
    if not private_key_pem or not server_public_key_pem:
        raise ValueError("As variáveis de ambiente SERVER_PRIVATE_KEY_PEM e SERVER_PUBLIC_KEY_PEM não foram definidas.")
    
    server_private_key = RSA.import_key(private_key_pem)
except Exception as e:
    logging.critical(f"ERRO CRÍTICO: Falha ao carregar as chaves RSA. A aplicação não pode operar de forma segura. Erro: {e}")

# --- CONEXÃO COM BANCO DE DADOS (POSTGRESQL) ---
def get_db_connection():
    conn = psycopg2.connect(os.getenv('DATABASE_URL'))
    return conn

# --- HELPERS ---
def generate_password_hash(password):
    salt = os.urandom(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return f"{salt.hex()}:{hash_obj.hex()}"

def verify_password(password, stored_hash):
    try:
        salt_hex, hash_hex = stored_hash.split(':')
        salt = bytes.fromhex(salt_hex)
        new_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()
        return new_hash == hash_hex
    except:
        return False

# --- DECORATORS DE CRIPTOGRAFIA E AUTENTICAÇÃO ---
def decrypt_request(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not server_private_key:
            return jsonify({'error': 'Criptografia do servidor não configurada'}), 503
        try:
            encrypted_payload = request.get_json()
            encrypted_key_b64 = encrypted_payload['encrypted_key']
            iv_b64 = encrypted_payload['iv']
            data_b64 = encrypted_payload['data']

            cipher_rsa = PKCS1_OAEP.new(server_private_key)
            session_key = cipher_rsa.decrypt(base64.b64decode(encrypted_key_b64))

            iv = base64.b64decode(iv_b64)
            cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
            
            decrypted_data = unpad(cipher_aes.decrypt(base64.b64decode(data_b64)), AES.block_size)
            
            request.json_decrypted = json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            logging.error(f"Falha na decriptografia: {e}")
            return jsonify({'error': 'Falha ao decriptografar a requisição'}), 400
        return f(*args, **kwargs)
    return decorated_function

def encrypt_response(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # A resposta da função de rota (e.g., dados do banco)
        response_data, status_code = f(*args, **kwargs)
        
        # Pega o ID do cliente da requisição para encontrar a chave pública correta
        client_id = request.headers.get('X-Client-ID')
        client_public_key_pem = client_public_keys.get(client_id)

        if not client_public_key_pem:
            return jsonify({'error': 'Chave pública do cliente não registrada'}), 400

        try:
            client_public_key = RSA.import_key(client_public_key_pem)
            
            session_key = os.urandom(32) # AES-256
            iv = os.urandom(16) # IV para AES-CBC

            cipher_rsa = PKCS1_OAEP.new(client_public_key)
            encrypted_key = cipher_rsa.encrypt(session_key)

            cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
            data_to_encrypt = json.dumps(response_data.get_json()).encode('utf-8')
            encrypted_data = cipher_aes.encrypt(pad(data_to_encrypt, AES.block_size))

            encrypted_payload = {
                'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'data': base64.b64encode(encrypted_data).decode('utf-8')
            }
            return jsonify(encrypted_payload), status_code
        except Exception as e:
            logging.error(f"Falha na criptografia da resposta: {e}")
            return jsonify({'error': 'Falha ao criptografar a resposta'}), 500
    return decorated_function

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'error': 'Token é obrigatório'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT * FROM usuarios WHERE id = %s", (data['user_id'],))
            current_user = cur.fetchone()
            cur.close()
            conn.close()
            if not current_user:
                return jsonify({'error': 'Usuário não encontrado'}), 404
            g.current_user = current_user
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirou'}), 401
        except Exception as e:
            return jsonify({'error': 'Token inválido', 'details': str(e)}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if g.current_user.get('role') != 'admin':
            return jsonify({'error': 'Acesso de administrador necessário'}), 403
        return f(*args, **kwargs)
    return decorated

# --- ROTAS DE SEGURANÇA E AUTENTICAÇÃO ---
@app.route('/api/security/public-key', methods=['GET'])
def get_server_public_key():
    if not server_public_key_pem:
        return jsonify({'error': 'Chave pública do servidor não está disponível'}), 503
    return jsonify({'public_key': server_public_key_pem})

@app.route('/api/security/register-key', methods=['POST'])
def register_client_key():
    data = request.get_json()
    public_key = data.get('public_key')
    if not public_key:
        return jsonify({'error': 'Chave pública do cliente não fornecida'}), 400
    
    client_id = str(uuid.uuid4())
    client_public_keys[client_id] = public_key
    
    # Retorna o ID para o cliente usar em futuras requisições
    return jsonify({'client_id': client_id, 'message': 'Chave registrada com sucesso'}), 200

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Usuário e senha são obrigatórios'}), 400

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM usuarios WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user or not verify_password(password, user['password']):
        return jsonify({'error': 'Credenciais inválidas'}), 401

    access_token = jwt.encode(
        {'user_id': user['id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)},
        app.config['SECRET_KEY'], algorithm='HS256'
    )
    refresh_token = jwt.encode(
        {'user_id': user['id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)},
        app.config['SECRET_KEY'], algorithm='HS256'
    )
    
    # Remove a senha do objeto de usuário retornado
    del user['password']

    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': user
    })

@app.route('/api/token/refresh', methods=['POST'])
def refresh():
    data = request.get_json()
    refresh_token = data.get('refresh_token')
    if not refresh_token:
        return jsonify({'error': 'Refresh token é obrigatório'}), 400
    try:
        payload = jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        # Opcional: Verificar se o usuário ainda existe/está ativo
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM usuarios WHERE id = %s", (user_id,))
        if not cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({'error': 'Usuário não encontrado'}), 401
        cur.close()
        conn.close()

        new_access_token = jwt.encode(
            {'user_id': user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)},
            app.config['SECRET_KEY'], algorithm='HS256'
        )
        return jsonify({'access_token': new_access_token})
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Refresh token expirou, faça login novamente'}), 401
    except Exception as e:
        return jsonify({'error': 'Refresh token inválido', 'details': str(e)}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    # Em um sistema com blacklist de tokens, o token seria adicionado aqui.
    # Como estamos usando tokens de curta duração, o logout no cliente é suficiente.
    return jsonify({'message': 'Logout bem-sucedido'}), 200

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email é obrigatório'}), 400

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id FROM usuarios WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user:
        reset_token = jwt.encode(
            {'user_id': user['id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            app.config['SECRET_KEY'], algorithm='HS256'
        )
        reset_url = f"http://127.0.0.1:5500/#reset-password/{reset_token}" # URL do seu frontend
        
        try:
            msg = Message("Recuperação de Senha - Cemitério Online",
                          recipients=[email])
            msg.body = f"Para redefinir sua senha, clique no link a seguir: {reset_url}"
            mail.send(msg)
        except Exception as e:
            logging.error(f"Falha ao enviar e-mail de recuperação: {e}")
            return jsonify({'error': 'Não foi possível enviar o e-mail de recuperação'}), 500

    # Resposta genérica para não revelar se um e-mail existe no sistema
    return jsonify({'message': 'Se o e-mail estiver cadastrado, um link de recuperação foi enviado.'}), 200

@app.route('/api/reset-password/<token>', methods=['POST'])
def reset_password(token):
    data = request.get_json()
    new_password = data.get('password')
    if not new_password:
        return jsonify({'error': 'Nova senha é obrigatória'}), 400
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        hashed_password = generate_password_hash(new_password)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE usuarios SET password = %s WHERE id = %s", (hashed_password, user_id))
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({'message': 'Senha redefinida com sucesso'}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token de redefinição expirou'}), 401
    except Exception as e:
        return jsonify({'error': 'Token de redefinição inválido', 'details': str(e)}), 401

# --- ROTAS DE CRUD (USUÁRIOS, SETORES, ETC.) ---

# Rota de status da API
@app.route('/api', methods=['GET'])
def api_root():
    return jsonify({
        'status': 'API is running',
        'version': '1.0.1',
    })

# --- USUARIOS ---
@app.route('/api/usuarios', methods=['GET', 'POST'])
def usuarios_collection():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    if request.method == 'GET':
        # Apenas admins podem listar todos os usuários
        # @admin_required já faria isso, mas para ser explícito:
        auth_header = request.headers.get('Authorization')
        if not auth_header: return jsonify({'error': 'Token é obrigatório'}), 401
        try:
            # Decodifica o token para verificar o role sem usar o decorator completo
            token = auth_header.split(" ")[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            cur.execute("SELECT role FROM usuarios WHERE id = %s", (data['user_id'],))
            user_role = cur.fetchone()
            if not user_role or user_role['role'] != 'admin':
                return jsonify({'error': 'Acesso negado'}), 403
        except:
            return jsonify({'error': 'Token inválido ou expirado'}), 401

        cur.execute('SELECT id, name, username, email, role FROM usuarios')
        data = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(data)
    
    if request.method == 'POST':
        # POST pode ser para criar conta (público) ou por admin
        p = getattr(request, 'json_decrypted', request.json or {})
        
        # Validação
        if not all(k in p for k in ['name', 'username', 'password']):
            return jsonify({'error': 'Nome, usuário e senha são obrigatórios'}), 400

        hashed_password = generate_password_hash(p.get('password'))
        
        # Se um admin está criando, ele pode definir o role. Senão, é 'visitante'.
        role = p.get('role', 'visitante')
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(" ")[1]
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                cur.execute("SELECT role FROM usuarios WHERE id = %s", (data['user_id'],))
                user_role = cur.fetchone()
                if not user_role or user_role['role'] != 'admin':
                    role = 'visitante' # Força role se o usuário não for admin
            except:
                role = 'visitante' # Força role se o token for inválido
        
        try:
            cur.execute('INSERT INTO usuarios (name, username, email, password, role) VALUES (%s,%s,%s,%s,%s) RETURNING id',
                        (p.get('name'), p.get('username'), p.get('email'), hashed_password, role))
            uid = cur.fetchone()['id']
            conn.commit()
            return jsonify({'id': uid}), 201
        except psycopg2.IntegrityError: # Captura erro de username/email duplicado
            conn.rollback()
            return jsonify({'error': 'Usuário ou email já existe'}), 409
        finally:
            cur.close()
            conn.close()

@app.route('/api/usuarios/<int:uid>', methods=['GET', 'PUT', 'DELETE'])
@token_required
def usuarios_single(uid):
    # Usuário só pode ver/editar/deletar a si mesmo, a menos que seja admin
    if g.current_user['role'] != 'admin' and g.current_user['id'] != uid:
        return jsonify({'error': 'Acesso negado'}), 403

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == 'GET':
        cur.execute('SELECT id, name, username, email, role FROM usuarios WHERE id=%s', (uid,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        return jsonify(user) if user else ('', 404)

    p = getattr(request, 'json_decrypted', request.json or {})

    if request.method == 'PUT':
        fields = []
        values = []
        if 'name' in p:
            fields.append('name=%s')
            values.append(p['name'])
        if 'username' in p:
            fields.append('username=%s')
            values.append(p['username'])
        if 'email' in p:
            fields.append('email=%s')
            values.append(p['email'])
        if 'password' in p and p['password']:
            fields.append('password=%s')
            values.append(generate_password_hash(p['password']))
        # Apenas admin pode mudar o role
        if 'role' in p and g.current_user['role'] == 'admin':
            fields.append('role=%s')
            values.append(p['role'])
        
        if not fields:
            return jsonify({'error': 'Nenhum campo para atualizar'}), 400

        values.append(uid)
        cur.execute(f'UPDATE usuarios SET {", ".join(fields)} WHERE id=%s', tuple(values))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'ok': True})

    if request.method == 'DELETE':
        cur.execute('DELETE FROM usuarios WHERE id=%s', (uid,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'ok': True})

# --- SETORES ---
@app.route('/api/setores', methods=['GET', 'POST'])
def setores_collection():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    if request.method == 'GET':
        cur.execute('SELECT id, name, vagas FROM setores')
        data = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(data)
    
    if request.method == 'POST':
        # Apenas admin pode criar
        return admin_required(lambda: _create_setor(cur, conn))()

def _create_setor(cur, conn):
    p = getattr(request, 'json_decrypted', request.json or {})
    cur.execute('INSERT INTO setores (name, vagas) VALUES (%s,%s) RETURNING id', (p.get('name'), p.get('vagas')))
    nid = cur.fetchone()['id']
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'id': nid}), 201

@app.route('/api/setores/<int:sid>', methods=['GET', 'PUT', 'DELETE'])
def setores_single(sid):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == 'GET':
        cur.execute('SELECT id, name, vagas FROM setores WHERE id=%s', (sid,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        return jsonify(row) if row else ('', 404)
    
    # Apenas admin pode alterar/deletar
    return admin_required(lambda: _update_delete_setor(cur, conn, sid))()

def _update_delete_setor(cur, conn, sid):
    if request.method == 'PUT':
        p = getattr(request, 'json_decrypted', request.json or {})
        cur.execute('UPDATE setores SET name=%s, vagas=%s WHERE id=%s', (p.get('name'), p.get('vagas'), sid))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'ok': True})
    
    if request.method == 'DELETE':
        cur.execute('DELETE FROM setores WHERE id=%s', (sid,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'ok': True})

# --- FALECIDOS ---
@app.route('/api/falecidos', methods=['GET', 'POST'])
@token_required
def falecidos_collection():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == 'GET':
        if g.current_user['role'] == 'admin':
            cur.execute("""
                SELECT f.id, f.name, f.anoNascimento, f.anoMorte, s.name AS setor_nome, f.vaga
                FROM falecidos f LEFT JOIN setores s ON f.setor = s.id
            """)
        else:
            cur.execute("""
                SELECT f.id, f.name, f.anoNascimento, f.anoMorte, s.name AS setor_nome, f.vaga
                FROM falecidos f
                JOIN usuarios_falecidos uf ON f.id = uf.falecido_id
                LEFT JOIN setores s ON f.setor = s.id
                WHERE uf.user_id = %s
            """, (g.current_user['id'],))
        data = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(data)

    if request.method == 'POST':
        if g.current_user['role'] != 'admin':
            return jsonify({'error': 'Acesso negado'}), 403
        
        p = getattr(request, 'json_decrypted', request.json or {})
        cur.execute('INSERT INTO falecidos (name, anoNascimento, anoMorte, setor, vaga) VALUES (%s,%s,%s,%s,%s) RETURNING id',
                    (p.get('name'), p.get('anoNascimento'), p.get('anoMorte'), p.get('setor'), p.get('vaga')))
        nid = cur.fetchone()['id']
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'id': nid}), 201

# --- PEDIDOS ---
@app.route('/api/pedidos', methods=['GET', 'POST'])
@token_required
def pedidos_collection():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == 'POST':
        p = getattr(request, 'json_decrypted', request.json or {})
        try:
            # CPF é hasheado no frontend, aqui apenas armazenamos
            cur.execute(
                'INSERT INTO pedidos (user_id, nome, cpf, email, telefone, forma_pagamento, total, status, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id',
                (g.current_user['id'], p.get('nome'), p.get('cpf'), p.get('email'), p.get('telefone'), p.get('forma_pagamento'), p.get('total'), 'pendente', datetime.datetime.utcnow())
            )
            pid = cur.fetchone()['id']
            for it in p.get('itens', []):
                cur.execute(
                    'INSERT INTO pedido_itens (pedido_id, produto_id, quantidade, preco) VALUES (%s,%s,%s,%s)',
                    (pid, it.get('produto_id'), it.get('quantidade'), it.get('preco'))
                )
            conn.commit()
            return jsonify({'id': pid}), 201
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error creating order: {e}")
            return jsonify({'error': 'internal server error'}), 500
        finally:
            cur.close()
            conn.close()

    if request.method == 'GET':
        if g.current_user['role'] == 'admin':
            cur.execute("SELECT * FROM pedidos ORDER BY created_at DESC")
        else:
            cur.execute("SELECT * FROM pedidos WHERE user_id = %s ORDER BY created_at DESC", (g.current_user['id'],))
        pedidos = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(pedidos)

@app.route('/api/pedidos/<int:pedido_id>/aprovar', methods=['PUT'])
@admin_required
def aprovar_pedido(pedido_id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        payload = request.get_json()
        novo_status = payload.get('status')
        if not novo_status:
            return jsonify({'error': 'Status é obrigatório'}), 400
        cur.execute('UPDATE pedidos SET status = %s WHERE id = %s', (novo_status, pedido_id))
        conn.commit()
        return jsonify({'message': 'Status do pedido atualizado com sucesso'}), 200
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error updating order status: {e}")
        return jsonify({'error': 'internal server error'}), 500
    finally:
        cur.close()
        conn.close()

# --- FINANCEIRO ---
@app.route('/api/financeiro', methods=['GET', 'POST'])
@admin_required
def financeiro_collection():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    if request.method == 'GET':
        cur.execute('SELECT id, tipo, descricao, valor, data, status FROM financeiro')
        data = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(data)
    
    if request.method == 'POST':
        p = getattr(request, 'json_decrypted', request.json or {})
        tipo_map = {'receita': 'Entrada', 'despesa': 'Saída'}
        tipo_db = tipo_map.get(p.get('tipo', '').lower())
        if not tipo_db:
            return jsonify({'error': 'Tipo inválido'}), 400
        try:
            cur.execute('INSERT INTO financeiro (tipo, descricao, valor, data) VALUES (%s,%s,%s,%s) RETURNING id',
                        (tipo_db, p.get('descricao'), p.get('valor'), p.get('data')))
            nid = cur.fetchone()['id']
            conn.commit()
            return jsonify({'id': nid}), 201
        except Exception as e:
            conn.rollback()
            return jsonify({'error': str(e)}), 500
        finally:
            cur.close()
            conn.close()

@app.route('/api/financeiro/<int:fid>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def financeiro_single(fid):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == 'GET':
        cur.execute('SELECT id, tipo, descricao, valor, data, status FROM financeiro WHERE id=%s', (fid,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        return jsonify(row) if row else ('', 404)

    if request.method == 'PUT':
        p = request.get_json()
        tipo_map = {'receita': 'Entrada', 'despesa': 'Saída'}
        tipo_db = tipo_map.get(p.get('tipo', '').lower())
        if not tipo_db:
            return jsonify({'error': 'Tipo inválido'}), 400
        cur.execute('UPDATE financeiro SET tipo=%s, descricao=%s, valor=%s, data=%s, status=%s WHERE id=%s',
                    (tipo_db, p.get('descricao'), p.get('valor'), p.get('data'), p.get('status'), fid))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'ok': True})

    if request.method == 'DELETE':
        cur.execute('DELETE FROM financeiro WHERE id=%s', (fid,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'ok': True})

# --- CATÁLOGO E CARRINHO (ROTAS PÚBLICAS/SIMPLES) ---
@app.route('/api/catalogo', methods=['GET'])
def catalogo_collection():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT id, nome, descricao, preco FROM catalogo')
    data = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(data)

@app.route('/api/carrinho', methods=['GET', 'POST', 'DELETE'])
def carrinho_collection():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    user_id = request.args.get('user_id')

    if request.method == 'GET':
        if user_id:
            cur.execute('SELECT id, user_id, produto_id, quantidade FROM carrinho WHERE user_id=%s', (user_id,))
        else: # Fallback para carrinho anônimo, se aplicável
            return jsonify([])
        data = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(data)

    if request.method == 'POST':
        p = request.get_json()
        cur.execute('INSERT INTO carrinho (user_id, produto_id, quantidade) VALUES (%s,%s,%s) RETURNING id',
                    (p.get('user_id'), p.get('produto_id'), p.get('quantidade')))
        nid = cur.fetchone()['id']
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'id': nid}), 201

    if request.method == 'DELETE':
        if user_id:
            cur.execute('DELETE FROM carrinho WHERE user_id=%s', (user_id,))
            conn.commit()
            cur.close()
            conn.close()
            return jsonify({'ok': True})
        return jsonify({'error': 'user_id é obrigatório para limpar o carrinho'}), 400

@app.route('/api/carrinho/<int:item_id>', methods=['PUT', 'DELETE'])
def carrinho_item(item_id):
    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'PUT':
        p = request.get_json()
        cur.execute('UPDATE carrinho SET quantidade=%s WHERE id=%s', (p.get('quantidade'), item_id))
    if request.method == 'DELETE':
        cur.execute('DELETE FROM carrinho WHERE id=%s', (item_id,))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'ok': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=False)