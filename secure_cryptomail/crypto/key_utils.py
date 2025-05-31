from cryptography.hazmat.primitives import serialization

def save_private_key(key, path):
    with open(path, 'wb') as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))

def save_public_key(key, path):
    with open(path, 'wb') as f:
        f.write(key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))

def load_private_key(path):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path):
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())