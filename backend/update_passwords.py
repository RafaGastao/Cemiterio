import mysql.connector
import os
import hashlib
from mysql.connector import Error
from config import DB_CONFIG

# Helper: Generate password hash with salt
def generate_password_hash(password):
    salt = os.urandom(16)  # Generate a 16-byte salt
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + ':' + hash_obj.hex()

def update_passwords():
    try:
        conn = mysql.connector.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            database=DB_CONFIG['database'],
            port=DB_CONFIG.get('port', 3306)
        )
        cur = conn.cursor()

        # Fetch all users
        cur.execute('SELECT id, password FROM usuarios')
        users = cur.fetchall()

        for user_id, plain_password in users:
            if ':' not in plain_password:  # Skip if already hashed
                hashed_password = generate_password_hash(plain_password)
                cur.execute('UPDATE usuarios SET password = %s WHERE id = %s', (hashed_password, user_id))
                print(f"Updated password for user ID {user_id}")

        conn.commit()
        cur.close()
        conn.close()
        print("Password update completed.")
    except Error as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    update_passwords()
