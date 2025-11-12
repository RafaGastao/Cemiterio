# Este script gera um par de chaves RSA (privada e pública) para ser usado no servidor.
# Execute este script UMA VEZ localmente e configure as saídas como variáveis de ambiente no seu provedor de hospedagem (Render).

from Crypto.PublicKey import RSA

def generate_and_print_keys():
    """
    Gera um par de chaves RSA de 2048 bits e imprime em formato PEM.
    """
    try:
        # Instale a dependência com: pip install pycryptodome
        key = RSA.generate(2048)

        private_key_pem = key.export_key().decode('utf-8')
        public_key_pem = key.publickey().export_key().decode('utf-8')

        print("--- Chave Privada do Servidor (SERVER_PRIVATE_KEY_PEM) ---")
        print("Copie e cole este bloco inteiro, incluindo as linhas BEGIN/END.")
        print(private_key_pem)
        print("\n" + "="*60 + "\n")

        print("--- Chave Pública do Servidor (SERVER_PUBLIC_KEY_PEM) ---")
        print("Copie e cole este bloco inteiro, incluindo as linhas BEGIN/END.")
        print(public_key_pem)
        print("\n" + "="*60 + "\n")
        
        print("Instruções:")
        print("1. Vá para o painel do seu serviço no Render.")
        print("2. Navegue até a seção 'Environment'.")
        print("3. Crie duas novas variáveis de ambiente:")
        print("   - Key: SERVER_PRIVATE_KEY_PEM, Value: (cole a chave privada gerada acima)")
        print("   - Key: SERVER_PUBLIC_KEY_PEM, Value: (cole a chave pública gerada acima)")
        print("4. Salve as alterações. O Render irá reiniciar seu serviço com as novas variáveis.")

    except ModuleNotFoundError:
        print("\nERRO: A biblioteca 'pycryptodome' não está instalada.")
        print("Execute o comando: pip install -r requirements.txt\n")
    except Exception as e:
        print(f"Ocorreu um erro ao gerar as chaves: {e}")

if __name__ == '__main__':
    generate_and_print_keys()
