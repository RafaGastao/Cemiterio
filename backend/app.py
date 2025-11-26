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
    cur.execute("SELECT id, name, email FROM usuarios WHERE email = %s AND username = %s", (email, username))
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
        # Retorna o token, o nome e o email do usuário para o frontend
        return jsonify({'token': token, 'user_name': user['name'], 'user_email': user['email']}), 200
    else:
        cur.close()
        conn.close()
        # Resposta de erro se a combinação não for encontrada
        return jsonify({'error': 'Usuário ou email inválido'}), 404