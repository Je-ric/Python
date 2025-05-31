import os
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()
KEY_ENV_VAR = 'VAULT_KEY'


def generate_key():
    try:
        key = Fernet.generate_key()
        with open('.env', 'a') as env_file:
            env_file.write(f"{KEY_ENV_VAR}={key.decode()}\n")
        return key
    except Exception as e:
        raise ValueError(f"[Error] Failed to generate/store encryption key: {e}")


def load_key():
    key = os.getenv(KEY_ENV_VAR)
    if key:
        try:
            return key.encode()
        except Exception as e:
            raise ValueError(f"[Error] Invalid key format in .env: {e}")
    else:
        print("[Info] No existing key found. Generating new one.")
        return generate_key()


# Initialize Fernet
try:
    fernet = Fernet(load_key())
except Exception as e:
    raise ValueError(f"[Fatal] Failed to initialize encryption system: {e}")
    raise SystemExit(1)


def encrypt_file(input_path, output_path):
    try:
        with open(input_path, 'rb') as f:
            data = f.read()
        enc = fernet.encrypt(data)
        with open(output_path, 'wb') as f:
            f.write(enc)
        print(f"[Success] Encrypted: {input_path} → {output_path}")
    except FileNotFoundError:
        raise ValueError(f"File not found: {input_path}")
    except PermissionError:
        raise ValueError(f"Permission denied when accessing: {input_path}")
    except Exception as e:
        raise ValueError(f"Failed to encrypt file: {e}")


def decrypt_file(input_path, output_path):
    try:
        with open(input_path, 'rb') as f:
            data = f.read()
        dec = fernet.decrypt(data)
        with open(output_path, 'wb') as f:
            f.write(dec)
        print(f"[Success] Decrypted: {input_path} → {output_path}")
    except FileNotFoundError:
        raise ValueError(f"File not found: {input_path}")
    except PermissionError:
        raise ValueError(f"Permission denied when accessing: {input_path}")
    except InvalidToken:
        raise ValueError(f"Invalid token. Cannot decrypt: {input_path}")
    except Exception as e:
        raise ValueError(f"Failed to decrypt file: {e}")
