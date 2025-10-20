import mysql.connector
import hashlib
import os

from flask import Flask, jsonify, request 
from flask_cors import CORS 

from mysql.connector import Error
from config import DB_CONFIG
import jwt 
import datetime

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["http://127.0.0.1:5500", "http://localhost:5500"]}})
app.config['SECRET_KEY'] = 'muda_essa_chave_para_producao'


def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            database=DB_CONFIG['database'],
            port=DB_CONFIG.get('port', 3306)
        )
        return conn
    except Error as e:
        print('DB connection error:', e)
        return None


# Helper: fetch all rows as list of dicts
def rows_to_dicts(cursor):
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]

# Helper: Generate password hash with salt
def generate_password_hash(password):
    salt = os.urandom(16)  # Generate a 16-byte salt
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + ':' + hash_obj.hex()

# Helper: Verify password hash
def verify_password(password, stored_hash):
    salt, hash_value = stored_hash.split(':')
    salt = bytes.fromhex(salt)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return hash_obj.hex() == hash_value

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

        user = dict(zip([c[0] for c in cur.description], row))
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
        data = rows_to_dicts(cur)
        cur.close(); conn.close();
        return jsonify(data)
    else:
        payload = request.json or {}
        hashed_password = generate_password_hash(payload.get('password'))  # Hash the password
        cur.execute('INSERT INTO usuarios (name, username, email, password, role) VALUES (%s,%s,%s,%s,%s)',
                    (payload.get('name'), payload.get('username'), payload.get('email'), hashed_password, payload.get('role','visitante')))
        conn.commit()
        uid = cur.lastrowid
        cur.close(); conn.close();
        return jsonify({'id': uid}), 201

@app.route('/api/usuarios/<int:uid>', methods=['GET','PUT','DELETE'])
def usuarios_single(uid):
    conn = get_db_connection()
    if not conn: return jsonify({'error':'db'}), 500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, name, username, email, role FROM usuarios WHERE id=%s', (uid,))
        row = cur.fetchone()
        if not row: cur.close(); conn.close(); return jsonify({}), 404
        user = dict(zip([c[0] for c in cur.description], row))
        cur.close(); conn.close();
        return jsonify(user)
    if request.method == 'PUT':
        p = request.json or {}
        hashed_password = generate_password_hash(p.get('password')) if p.get('password') else None
        cur.execute('UPDATE usuarios SET name=%s, username=%s, email=%s, password=%s, role=%s WHERE id=%s',
                    (p.get('name'), p.get('username'), p.get('email'), hashed_password, p.get('role'), uid))
        conn.commit(); cur.close(); conn.close();
        return jsonify({'ok':True})
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
        data = rows_to_dicts(cur)
        cur.close(); conn.close();
        return jsonify(data)
    else:
        p = request.json or {}
        cur.execute('INSERT INTO setores (name, vagas) VALUES (%s,%s)', (p.get('name'), p.get('vagas')))
        conn.commit(); nid = cur.lastrowid
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
        res = dict(zip([c[0] for c in cur.description], row)); cur.close(); conn.close(); return jsonify(res)
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
        setores = rows_to_dicts(cur)

        for setor in setores:
            cur.execute("""
                SELECT f.vaga
                FROM falecidos f
                WHERE f.setor = %s
            """, (setor['setor_id'],))
            ocupadas = [row['vaga'] for row in rows_to_dicts(cur)]
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
            GROUP BY s.vagas
        """, (setor_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'Setor não encontrado'}), 404

        vagas, ocupadas = row
        disponiveis = vagas - ocupadas
        if disponiveis <= 0:
            return jsonify({'error': 'Não há vagas disponíveis neste setor'}), 400

        # Inserir um novo registro de falecido para ocupar a vaga
        payload = request.json or {}
        cur.execute("""
            INSERT INTO falecidos (name, anoNascimento, anoMorte, setor)
            VALUES (%s, %s, %s, %s)
        """, (payload.get('name'), payload.get('anoNascimento'), payload.get('anoMorte'), setor_id))
        conn.commit()
        return jsonify({'message': 'Vaga ocupada com sucesso', 'id': cur.lastrowid}), 201
    except Exception as e:
        print(f"Error occupying vaga: {e}")
        return jsonify({'error': 'internal server error'}), 500
    finally:
        cur.close()
        conn.close()


# --- Falecidos CRUD ---
@app.route('/api/falecidos', methods=['GET', 'POST'])
def falecidos_collection():
    conn = get_db_connection()
    if not conn:
        return jsonify([]), 500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, name, anoNascimento, anoMorte, setor, vaga FROM falecidos')
        data = rows_to_dicts(cur)
        cur.close()
        conn.close()
        return jsonify(data)
    else:
        p = request.json or {}
        setor = p.get('setor')
        vaga = p.get('vaga')

        # Verificar se a vaga está disponível
        cur.execute(
            'SELECT COUNT(*) FROM falecidos WHERE setor = %s AND vaga = %s',
            (setor, vaga)
        )
        if cur.fetchone()[0] > 0:
            cur.close()
            conn.close()
            return jsonify({'error': 'A vaga selecionada já está ocupada.'}), 400

        # Inserir o falecido e ocupar a vaga
        cur.execute(
            'INSERT INTO falecidos (name, anoNascimento, anoMorte, setor, vaga) VALUES (%s, %s, %s, %s, %s)',
            (p.get('name'), p.get('anoNascimento'), p.get('anoMorte'), setor, vaga)
        )
        conn.commit()
        nid = cur.lastrowid
        cur.close()
        conn.close()
        return jsonify({'id': nid}), 201

@app.route('/api/falecidos/<int:fid>', methods=['GET','PUT','DELETE'])
def falecidos_single(fid):
    conn = get_db_connection();
    if not conn: return jsonify({'error':'db'}),500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, name, anoNascimento, anoMorte, setor FROM falecidos WHERE id=%s', (fid,))
        row = cur.fetchone();
        if not row: cur.close(); conn.close(); return jsonify({}),404
        res = dict(zip([c[0] for c in cur.description], row)); cur.close(); conn.close(); return jsonify(res)
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
            SELECT COUNT(*) FROM falecidos WHERE setor = %s AND vaga = %s
        """, (setor, vaga))
        if cur.fetchone()[0] > 0:
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


# --- Catálogo ---
@app.route('/api/catalogo', methods=['GET','POST'])
def catalogo_collection():
    conn = get_db_connection();
    if not conn: return jsonify([]),500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, nome, descricao, preco FROM catalogo')
        data = rows_to_dicts(cur); cur.close(); conn.close(); return jsonify(data)
    else:
        p = request.json or {}
        cur.execute('INSERT INTO catalogo (nome, descricao, preco) VALUES (%s,%s,%s)', (p.get('nome'), p.get('descricao'), p.get('preco')))
        conn.commit(); nid = cur.lastrowid; cur.close(); conn.close(); return jsonify({'id':nid}),201


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
        data = rows_to_dicts(cur); cur.close(); conn.close(); return jsonify(data)
    if request.method == 'POST':
        p = request.json or {}
        # espera: produto_id, quantidade, user_id (pode ser null)
        cur.execute('INSERT INTO carrinho (user_id, produto_id, quantidade) VALUES (%s,%s,%s)', (p.get('user_id'), p.get('produto_id'), p.get('quantidade')))
        conn.commit(); nid = cur.lastrowid; cur.close(); conn.close(); return jsonify({'id':nid}),201
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
        res = dict(zip([c[0] for c in cur.description], row)); cur.close(); conn.close(); return jsonify(res)
    if request.method == 'PUT':
        p = request.json or {}
        cur.execute('UPDATE carrinho SET quantidade=%s WHERE id=%s', (p.get('quantidade'), item_id))
        conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})
    if request.method == 'DELETE':
        cur.execute('DELETE FROM carrinho WHERE id=%s', (item_id,)); conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})


# --- Pedidos (checkout) ---
@app.route('/api/pedidos', methods=['POST','GET'])
def pedidos_collection():
    conn = get_db_connection();
    if not conn: return jsonify({'error':'db'}),500
    cur = conn.cursor()
    if request.method == 'POST':
        p = request.json or {}
        cur.execute('INSERT INTO pedidos (user_id, nome, cpf, email, telefone, forma_pagamento, total, status, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                    (p.get('user_id'), p.get('nome'), p.get('cpf'), p.get('email'), p.get('telefone'), p.get('forma_pagamento'), p.get('total'), 'pendente', datetime.datetime.utcnow()))
        pid = cur.lastrowid
        # inserir itens
        for it in p.get('itens',[]):
            cur.execute('INSERT INTO pedido_itens (pedido_id, produto_id, quantidade, preco) VALUES (%s,%s,%s,%s)', (pid, it.get('produto_id'), it.get('quantidade'), it.get('preco')))
        conn.commit(); cur.close(); conn.close();
        return jsonify({'id':pid}),201
    else:
        cur.execute('SELECT id, user_id, nome, cpf, email, telefone, forma_pagamento, total, status, created_at FROM pedidos')
        data = rows_to_dicts(cur); cur.close(); conn.close(); return jsonify(data)


# --- Financeiro ---
@app.route('/api/financeiro', methods=['GET','POST'])
def financeiro_collection():
    conn = get_db_connection();
    if not conn: return jsonify([]),500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, tipo, descricao, valor, data FROM financeiro')
        data = rows_to_dicts(cur); cur.close(); conn.close(); return jsonify(data)
    else:
        p = request.json or {}
        cur.execute('INSERT INTO financeiro (tipo, descricao, valor, data) VALUES (%s,%s,%s,%s)', (p.get('tipo'), p.get('descricao'), p.get('valor'), p.get('data')))
        conn.commit(); nid = cur.lastrowid; cur.close(); conn.close(); return jsonify({'id':nid}),201

@app.route('/api/financeiro/<int:fid>', methods=['GET','PUT','DELETE'])
def financeiro_single(fid):
    conn = get_db_connection();
    if not conn: return jsonify({'error':'db'}),500
    cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id, tipo, descricao, valor, data FROM financeiro WHERE id=%s', (fid,))
        row = cur.fetchone();
        if not row: cur.close(); conn.close(); return jsonify({}),404
        res = dict(zip([c[0] for c in cur.description], row)); cur.close(); conn.close(); return jsonify(res)
    if request.method == 'PUT':
        p = request.json or {}
        cur.execute('UPDATE financeiro SET tipo=%s, descricao=%s, valor=%s, data=%s WHERE id=%s', (p.get('tipo'), p.get('descricao'), p.get('valor'), p.get('data'), fid))
        conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})
    if request.method == 'DELETE':
        cur.execute('DELETE FROM financeiro WHERE id=%s', (fid,)); conn.commit(); cur.close(); conn.close(); return jsonify({'ok':True})


if __name__ == '__main__':
    app.run( debug=True)