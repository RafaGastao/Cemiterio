import os
import psycopg2
import hashlib
from psycopg2.extras import RealDictCursor

# --- ATENÇÃO ---
# Execute este script UMA ÚNICA VEZ no seu ambiente de produção (Render)
# depois de fazer o deploy do novo código.
#
# ANTES DE EXECUTAR: FAÇA UM BACKUP DO SEU BANCO DE DADOS!
#
# Como executar no Render Shell:
# 1. Certifique-se de que suas variáveis de ambiente (DB_HOST, DB_USER, etc.) estão configuradas.
# 2. Execute o comando: python backend/migration.py

def get_db_connection():
    """Estabelece conexão com o banco de dados usando variáveis de ambiente."""
    try:
        conn = psycopg2.connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            dbname=os.getenv('DB_DATABASE'),
            port=int(os.getenv('DB_PORT', 5432)),
            cursor_factory=RealDictCursor
        )
        return conn
    except psycopg2.Error as e:
        print(f"Erro ao conectar ao banco de dados: {e}")
        return None

def hash_sensitive_data(data):
    """
    Função de hash IDÊNTICA à do app.py para garantir consistência.
    """
    salt = os.urandom(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', data.encode(), salt, 100000)
    return salt.hex() + ':' + hash_obj.hex()

def migrate_cpfs():
    """
    Encontra CPFs em texto puro na tabela 'pedidos' e aplica o hash.
    """
    conn = get_db_connection()
    if not conn:
        return

    cur = conn.cursor()
    try:
        # Seleciona apenas os pedidos onde o CPF não contém o separador ':'
        # Isso indica que o CPF está em texto puro e ainda não foi migrado.
        cur.execute("SELECT id, cpf FROM pedidos WHERE cpf IS NOT NULL AND POSITION(':' IN cpf) = 0")
        pedidos_para_migrar = cur.fetchall()

        if not pedidos_para_migrar:
            print("Nenhum CPF para migrar. O banco de dados já está atualizado.")
            return

        print(f"Encontrados {len(pedidos_para_migrar)} CPFs para migrar...")

        for pedido in pedidos_para_migrar:
            pedido_id = pedido['id']
            cpf_puro = pedido['cpf']

            if not cpf_puro:
                continue

            # Gera o hash para o CPF
            hashed_cpf = hash_sensitive_data(cpf_puro)

            # Atualiza o registro no banco de dados
            cur.execute("UPDATE pedidos SET cpf = %s WHERE id = %s", (hashed_cpf, pedido_id))
            print(f"CPF do pedido ID {pedido_id} migrado com sucesso.")

        conn.commit()
        print("\nMigração concluída com sucesso!")

    except Exception as e:
        conn.rollback()
        print(f"\nOcorreu um erro durante a migração: {e}")
        print("Todas as alterações foram desfeitas (rollback).")
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    print("--- INICIANDO SCRIPT DE MIGRAÇÃO DE CPFs ---")
    # Adicionando uma confirmação para segurança
    confirm = input("Você fez um backup do banco de dados? (s/n): ")
    if confirm.lower() == 's':
        migrate_cpfs()
    else:
        print("Migração cancelada. Por favor, faça um backup do banco de dados antes de continuar.")
    print("--- FIM DO SCRIPT ---")
