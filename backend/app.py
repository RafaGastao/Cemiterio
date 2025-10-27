import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
import os

from flask import Flask, jsonify, request, g, send_from_directory
from flask_cors import CORS 

import jwt 
import datetime

# Ajuste para servir arquivos estáticos da pasta raiz do projeto
app = Flask(__name__, static_folder='..', static_url_path='/')
# Modificado para usar variável de ambiente para a URL do frontend e ser mais específico na rota
frontend_url = os.getenv('FRONTEND_URL', 'http://127.0.0.1:5500')
CORS(app, resources={r"/api/*": {"origins": [frontend_url, "http://localhost:5500", "https://cemiterio-0elv.onrender.com"]}})
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'muda_essa_chave_para_producao')


def get_db_connection():
    try:
        conn = psycopg2.connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            dbname=os.getenv('DB_DATABASE'),
            port=int(os.getenv('DB_PORT', 5432)),
            cursor_factory=RealDictCursor  # Retorna linhas como dicionários
        )
        return conn
    except psycopg2.Error as e:
        print('DB connection error:', e)
        return None


# Helper: fetch all rows as list of dicts (NÃO MAIS NECESSÁRIO com RealDictCursor)
# def rows_to_dicts(cursor):
#     cols = [c[0] for c in cursor.description]
#     return [dict(zip(cols, row)) for row in cursor.fetchall()]

# Helper: Generate password hash with salt
def generate_password_hash(password):
    salt = os.urandom(16)  # Generate a 16-byte salt
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + ':' + hash_obj.hex()

# Helper: Verify password hash
def verify_password(password, stored_hash):
    try:
        salt, hash_value = stored_hash.split(':')
        salt = bytes.fromhex(salt)
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return hash_obj.hex() == hash_value
    except (ValueError, IndexError):
        # Lida com casos onde o split falha ou o hash não está no formato esperado.
        # Isso previne o crash da aplicação por senhas em formato antigo/inválido.
        return False

# Helper: Hash and salt sensitive data (e.g., CPF)
def hash_sensitive_data(data):
    salt = os.urandom(16)  # Generate a 16-byte salt
    hash_obj = hashlib.pbkdf2_hmac('sha256', data.encode(), salt, 100000)
    return salt.hex() + ':' + hash_obj.hex()

# Middleware para autenticação e obtenção do usuário atual
@app.before_request
def authenticate_user():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        g.current_user = None
        return
    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded.get('user_id')
        conn = get_db_connection()
        if not conn:  # <-- ADICIONAR ESTA VERIFICAÇÃO
            g.current_user = None
            return

        cur = conn.cursor()
        cur.execute('SELECT id, name, role FROM usuarios WHERE id = %s', (user_id,))
        user = cur.fetchone()
        if user:
            g.current_user = user # Já é um dicionário
        else:
            g.current_user = None
        cur.close()
        conn.close()
        print(f"Authenticated user: {g.current_user}")  # Adicione este log
    except Exception as e:
        print(f"Authentication error: {e}")
        g.current_user = None

# --- Rota para servir o frontend ---
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
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
    """Returns status message for the API root path."""
    return jsonify({
        'status': 'API is running',
        'version': '1.0',
        'available_routes': ['/api/login', '/api/usuarios', '/api/setores', '/api/falecidos', '/api/catalogo', '/api/carrinho', '/api/pedidos', '/api/financeiro']
    })
# --- END NEW ROUTE ---

# --- Auth: login (simples) ---
@app.route('/api/login', methods=['POST'])
def login():
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
        print(f"Login attempt: username={username}, stored_password={stored_password}")

        # Verify password hash
        if not verify_password(password, stored_password):
            return jsonify({'error': 'invalid credentials'}), 401

        token = jwt.encode(
            {'user_id': user['id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=8)},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        return jsonify({'token': token, 'user': {'id': user['id'], 'name': user['name'], 'role': user['role']}})
    except Exception as e:
        print(f"Error during login: {e}")
        return jsonify({'error': 'internal server error'}), 500
    finally:
        cur.close()
        conn.close()


# --- Usuarios CRUD (SEM AUTORIZAÇÃO NO POST) ---
@app.route('/api/usuarios', methods=['GET','POST'])
def usuarios_collection():
    conn = get_db_connection()
    if not conn: return jsonify([]), 500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, name, username, email, role FROM usuarios')
        data = cur.fetchall()
        cur.close(); conn.close();
        return jsonify(data)
    else:
        payload = request.json or {}
        hashed_password = generate_password_hash(payload.get('password'))  # Hash the password
        cur.execute('INSERT INTO usuarios (name, username, email, password, role) VALUES (%s,%s,%s,%s,%s) RETURNING id',
                    (payload.get('name'), payload.get('username'), payload.get('email'), hashed_password, payload.get('role','visitante')))
        uid = cur.fetchone()['id']
        conn.commit()
        cur.close(); conn.close();
        return jsonify({'id': uid}), 201

@app.route('/api/usuarios/<int:uid>', methods=['GET','PUT','DELETE'])
def usuarios_single(uid):
    conn = get_db_connection()
    if not conn: return jsonify({'error':'db'}), 500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, name, username, email, role FROM usuarios WHERE id=%s', (uid,))
        user = cur.fetchone()
        if not user: cur.close(); conn.close(); return jsonify({}), 404
        cur.close(); conn.close();
        return jsonify(user)
    if request.method == 'PUT':
        p = request.json or {}
        hashed_password = generate_password_hash(p.get('password')) if p.get('password') else None
        cur.execute('UPDATE usuarios SET name=%s, username=%s, email=%s, password=%s, role=%s WHERE id=%s',
                    (p.get('name'), p.get('username'), p.get('email'), hashed_password, p.get('role'), uid))
        conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})
    if request.method == 'DELETE':
        cur.execute('DELETE FROM usuarios WHERE id=%s', (uid,))
        conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})


# --- Setores CRUD ---
@app.route('/api/setores', methods=['GET','POST'])
def setores_collection():
    conn = get_db_connection();
    if not conn: return jsonify([]),500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, name, vagas FROM setores')
        data = cur.fetchall()
        cur.close(); conn.close();
        return jsonify(data)
    else:
        p = request.json or {}
        cur.execute('INSERT INTO setores (name, vagas) VALUES (%s,%s) RETURNING id', (p.get('name'), p.get('vagas')))
        nid = cur.fetchone()['id']
        conn.commit();
        cur.close(); conn.close();
        return jsonify({'id': nid}),201

@app.route('/api/setores/<int:sid>', methods=['GET','PUT','DELETE'])
def setores_single(sid):
    conn = get_db_connection();
    if not conn: return jsonify({'error':'db'}),500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, name, vagas FROM setores WHERE id=%s', (sid,))
        row = cur.fetchone();
        if not row: cur.close(); conn.close(); return jsonify({}),404
        cur.close(); conn.close(); return jsonify(row)
    if request.method == 'PUT':
        p = request.json or {}
        cur.execute('UPDATE setores SET name=%s, vagas=%s WHERE id=%s', (p.get('name'), p.get('vagas'), sid))
        conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})
    if request.method == 'DELETE':
        cur.execute('DELETE FROM setores WHERE id=%s', (sid,)); conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})

@app.route('/api/setores/vagas', methods=['GET'])
def listar_vagas():
    """Lista vagas ocupadas e disponíveis por setor, incluindo o status de cada vaga."""
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
        print(f"Error listing vagas: {e}")
        return jsonify({'error': 'internal server error'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/setores/<int:setor_id>/ocupar', methods=['POST'])
def ocupar_vaga(setor_id):
    """Ocupação de uma vaga em um setor."""
    conn = get_db_connection()
    if not conn: return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    try:
        # Verificar se há vagas disponíveis no setor
        cur.execute("""
            SELECT s.vagas, COUNT(f.id) AS ocupadas
            FROM setores s
            LEFT JOIN falecidos f ON s.id = f.setor
            WHERE s.id = %s
            GROUP BY s.id
        """, (setor_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'Setor não encontrado'}), 404

        vagas = row['vagas']
        ocupadas = row['ocupadas']
        disponiveis = vagas - ocupadas
        if disponiveis <= 0:
            return jsonify({'error': 'Não há vagas disponíveis neste setor'}), 400

        # Inserir um novo registro de falecido para ocupar a vaga
        payload = request.json or {}
        cur.execute("""
            INSERT INTO falecidos (name, anoNascimento, anoMorte, setor)
            VALUES (%s, %s, %s, %s) RETURNING id
        """, (payload.get('name'), payload.get('anoNascimento'), payload.get('anoMorte'), setor_id))
        new_id = cur.fetchone()['id']
        conn.commit()
        return jsonify({'message': 'Vaga ocupada com sucesso', 'id': new_id}), 201
    except Exception as e:
        print(f"Error occupying vaga: {e}")
        return jsonify({'error': 'internal server error'}), 500
    finally:
        cur.close()
        conn.close()


# --- Falecidos CRUD ---
@app.route('/api/falecidos', methods=['GET', 'POST'])
def falecidos_collection():
    """Lista falecidos com base no nível do usuário, incluindo nome do setor e planos associados."""
    conn = get_db_connection()
    if not conn:
        return jsonify([]), 500
    cur = conn.cursor()

    try:
        if g.current_user and g.current_user['role'] == 'visitante':
            # Visitantes só podem ver falecidos associados a eles
            cur.execute("""
                SELECT f.id, f.name, f.anoNascimento, f.anoMorte, s.name AS setor_nome, f.vaga,
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
                SELECT f.id, f.name, f.anoNascimento, f.anoMorte, s.name AS setor_nome, f.vaga,
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
        return jsonify(data)
    except Exception as e:
        print(f"Error fetching falecidos: {e}")
        return jsonify({'error': 'internal server error'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/falecidos/<int:fid>', methods=['GET','PUT','DELETE'])
def falecidos_single(fid):
    conn = get_db_connection();
    if not conn: return jsonify({'error':'db'}),500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, name, anoNascimento, anoMorte, setor FROM falecidos WHERE id=%s', (fid,))
        row = cur.fetchone();
        if not row: cur.close(); conn.close(); return jsonify({}),404
        cur.close(); conn.close(); return jsonify(row)
    if request.method == 'PUT':
        p = request.json or {}
        cur.execute('UPDATE falecidos SET name=%s, anoNascimento=%s, anoMorte=%s, setor=%s WHERE id=%s',
                    (p.get('name'), p.get('anoNascimento'), p.get('anoMorte'), p.get('setor'), fid))
        conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})
    if request.method == 'DELETE':
        cur.execute('DELETE FROM falecidos WHERE id=%s', (fid,)); conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})

@app.route('/api/falecidos/<int:fid>/atribuir-vaga', methods=['PUT'])
def atribuir_vaga(fid):
    """Atribui uma vaga a um usuário falecido existente."""
    conn = get_db_connection()
    if not conn: return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    try:
        payload = request.json or {}
        vaga = payload.get('vaga')
        setor = payload.get('setor')

        if not vaga or not setor:
            return jsonify({'error': 'vaga e setor são obrigatórios'}), 400

        # Verificar se a vaga já está ocupada
        cur.execute("""
            SELECT COUNT(*)::int FROM falecidos WHERE setor = %s AND vaga = %s
        """, (setor, vaga))
        if cur.fetchone()['count'] > 0:
            return jsonify({'error': 'Vaga já está ocupada'}), 400

        # Atualizar a vaga do falecido
        cur.execute("""
            UPDATE falecidos SET vaga = %s, setor = %s WHERE id = %s
        """, (vaga, setor, fid))
        conn.commit()
        return jsonify({'message': 'Vaga atribuída com sucesso'}), 200
    except Exception as e:
        print(f"Error assigning vaga: {e}")
        return jsonify({'error': 'internal server error'}), 500
    finally:
        cur.close()
        conn.close()

# --- Associar falecidos a usuários ---
@app.route('/api/falecidos/<int:fid>/associar', methods=['POST'])
def associar_falecido(fid):
    """Associa um falecido a um usuário."""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    try:
        payload = request.json or {}
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
            return jsonify({'error': 'Associação já existe'}), 400

        # Criar a associação
        cur.execute('INSERT INTO usuarios_falecidos (user_id, falecido_id) VALUES (%s, %s)', (user_id, fid))
        conn.commit()
        return jsonify({'message': 'Falecido associado ao usuário com sucesso'}), 201
    except Exception as e:
        print(f"Error associating falecido: {e}")
        return jsonify({'error': 'internal server error'}), 500
    finally:
        cur.close()
        conn.close()

# --- Listar falecidos associados a um usuário ---
@app.route('/api/usuarios/<int:user_id>/falecidos', methods=['GET'])
def listar_falecidos_usuario(user_id):
    """Lista os falecidos associados a um usuário."""
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
        print(f"Error listing falecidos for user: {e}")
        return jsonify({'error': 'internal server error'}), 500
    finally:
        cur.close()
        conn.close()

# --- Associar falecidos a planos ---
@app.route('/api/falecidos/<int:fid>/associar-plano', methods=['POST'])
def associar_plano(fid):
    """Associa um falecido a um plano."""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    try:
        payload = request.json or {}
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
        return jsonify({'message': 'Plano associado ao falecido com sucesso'}), 201
    except Exception as e:
        print(f"Error associating plano: {e}")
        return jsonify({'error': 'internal server error'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/falecidos/<int:fid>/planos', methods=['GET'])
def listar_planos_falecido(fid):
    """Lista os planos associados a um falecido."""
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
        print(f"Error listing planos for falecido: {e}")
        return jsonify({'error': 'internal server error'}), 500
    finally:
        cur.close()
        conn.close()


# --- Catálogo ---
@app.route('/api/catalogo', methods=['GET','POST'])
def catalogo_collection():
    conn = get_db_connection();
    if not conn: return jsonify([]),500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, nome, descricao, preco FROM catalogo')
        data = cur.fetchall(); cur.close(); conn.close(); return jsonify(data)
    else:
        p = request.json or {}
        cur.execute('INSERT INTO catalogo (nome, descricao, preco) VALUES (%s,%s,%s) RETURNING id', (p.get('nome'), p.get('descricao'), p.get('preco')))
        nid = cur.fetchone()['id']
        conn.commit(); cur.close(); conn.close(); return jsonify({'id':nid}),201


# --- Carrinho (persistência de itens antes do pedido) ---
@app.route('/api/carrinho', methods=['GET','POST','DELETE'])
def carrinho_collection():
    conn = get_db_connection();
    if not conn: return jsonify({'error':'db'}),500
    cur = conn.cursor()
    if request.method == 'GET':
        user_id = request.args.get('user_id')
        if user_id:
            cur.execute('SELECT id, user_id, produto_id, quantidade FROM carrinho WHERE user_id=%s', (user_id,))
        else:
            cur.execute('SELECT id, user_id, produto_id, quantidade FROM carrinho')
        data = cur.fetchall(); cur.close(); conn.close(); return jsonify(data)
    if request.method == 'POST':
        p = request.json or {}
        # espera: produto_id, quantidade, user_id (pode ser null)
        cur.execute('INSERT INTO carrinho (user_id, produto_id, quantidade) VALUES (%s,%s,%s) RETURNING id', (p.get('user_id'), p.get('produto_id'), p.get('quantidade')))
        nid = cur.fetchone()['id']
        conn.commit(); cur.close(); conn.close(); return jsonify({'id':nid}),201
    if request.method == 'DELETE':
        # permitir deleção por user_id query param (limpar carrinho) ou corpo ?user_id=
        user_id = request.args.get('user_id')
        if user_id:
            cur.execute('DELETE FROM carrinho WHERE user_id=%s', (user_id,))
            conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})
        else:
            cur.close(); conn.close(); return jsonify({'error':'user_id required to clear cart'}),400


@app.route('/api/carrinho/<int:item_id>', methods=['GET','PUT','DELETE'])
def carrinho_item(item_id):
    conn = get_db_connection();
    if not conn: return jsonify({'error':'db'}),500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, user_id, produto_id, quantidade FROM carrinho WHERE id=%s', (item_id,))
        row = cur.fetchone();
        if not row: cur.close(); conn.close(); return jsonify({}),404
        cur.close(); conn.close(); return jsonify(row)
    if request.method == 'PUT':
        p = request.json or {}
        cur.execute('UPDATE carrinho SET quantidade=%s WHERE id=%s', (p.get('quantidade'), item_id))
        conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})
    if request.method == 'DELETE':
        cur.execute('DELETE FROM carrinho WHERE id=%s', (item_id,)); conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})


# --- Pedidos (checkout) ---
@app.route('/api/pedidos', methods=['GET', 'POST'])
def pedidos_collection():
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'db'}), 500
    cur = conn.cursor()
    
    if request.method == 'POST':
        p = request.json or {}
        try:
            # Hash and salt the CPF
            hashed_cpf = hash_sensitive_data(p.get('cpf'))

            # Insert the order
            cur.execute(
                'INSERT INTO pedidos (user_id, nome, cpf, email, telefone, forma_pagamento, total, status, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id',
                (p.get('user_id'), p.get('nome'), hashed_cpf, p.get('email'), p.get('telefone'), p.get('forma_pagamento'), p.get('total'), 'pendente', datetime.datetime.utcnow())
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
            print(f"Error creating order: {e}")
            return jsonify({'error': 'internal server error'}), 500
        finally:
            cur.close()
            conn.close()

    if request.method == 'GET':
        """Lista pedidos realizados. Admins veem todos os pedidos, usuários veem apenas os próprios."""
        try:
            if g.current_user and g.current_user['role'] == 'admin':
                # Admins podem ver todos os pedidos
                cur.execute("""
                    SELECT p.id, p.user_id, u.name AS usuario, p.nome, p.email, p.telefone, p.forma_pagamento, p.total, p.status, p.created_at, p.aprovado
                    FROM pedidos p
                    LEFT JOIN usuarios u ON p.user_id = u.id
                """)
            elif g.current_user:
                # Usuários comuns veem apenas os próprios pedidos
                cur.execute("""
                    SELECT p.id, p.user_id, u.name AS usuario, p.nome, p.email, p.telefone, p.forma_pagamento, p.total, p.status, p.created_at, p.aprovado
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
            return jsonify(pedidos)
        except Exception as e:
            print(f"Error fetching pedidos: {e}")
            return jsonify({'error': 'internal server error'}), 500
        finally:
            cur.close()
            conn.close()


@app.route('/api/pedidos/<int:pedido_id>/aprovar', methods=['PUT'])
def aprovar_pedido(pedido_id):
    """Permite que o administrador aprove ou rejeite um pedido."""
    if not g.current_user or g.current_user['role'] != 'admin':
        return jsonify({'error': 'Acesso negado'}), 403

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'db connection error'}), 500
    cur = conn.cursor()
    try:
        payload = request.json or {}
        aprovado = payload.get('aprovado')  # True ou False
        if aprovado is None:
            return jsonify({'error': 'Campo "aprovado" é obrigatório'}), 400

        cur.execute('UPDATE pedidos SET aprovado = %s WHERE id = %s', (aprovado, pedido_id))
        conn.commit()
        return jsonify({'message': 'Status de aprovação atualizado com sucesso'}), 200
    except Exception as e:
        print(f"Error updating approval status: {e}")
        return jsonify({'error': 'internal server error'}), 500
    finally:
        cur.close()
        conn.close()


# --- Financeiro ---
@app.route('/api/financeiro', methods=['GET','POST'])
def financeiro_collection():
    conn = get_db_connection();
    if not conn: return jsonify([]),500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, tipo, descricao, valor, data FROM financeiro')
        data = cur.fetchall(); cur.close(); conn.close(); return jsonify(data)
    else:
        p = request.json or {}
        cur.execute('INSERT INTO financeiro (tipo, descricao, valor, data) VALUES (%s,%s,%s,%s) RETURNING id', (p.get('tipo'), p.get('descricao'), p.get('valor'), p.get('data')))
        nid = cur.fetchone()['id']
        conn.commit(); cur.close(); conn.close(); return jsonify({'id':nid}),201

@app.route('/api/financeiro/<int:fid>', methods=['GET','PUT','DELETE'])
def financeiro_single(fid):
    conn = get_db_connection();
    if not conn: return jsonify({'error':'db'}),500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, tipo, descricao, valor, data FROM financeiro WHERE id=%s', (fid,))
        row = cur.fetchone();
        if not row: cur.close(); conn.close(); return jsonify({}),404
        cur.close(); conn.close(); return jsonify(row)
    if request.method == 'PUT':
        p = request.json or {}
        cur.execute('UPDATE financeiro SET tipo=%s, descricao=%s, valor=%s, data=%s WHERE id=%s', (p.get('tipo'), p.get('descricao'), p.get('valor'), p.get('data'), fid))
        conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})
    if request.method == 'DELETE':
        cur.execute('DELETE FROM financeiro WHERE id=%s', (fid,)); conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})


if __name__ == '__main__':
    app.run( debug=True)