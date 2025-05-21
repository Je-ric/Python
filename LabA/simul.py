from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os

def generate_rsa_keys():
    # Generate User2's RSA private and public keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save private key
    with open("user2_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open("user2_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def encrypt_file(file_path, public_key_path):
    # Load User2's public key
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    # Generate AES key and IV
    aes_key = os.urandom(32)  # AES-256 key (32 bytes)
    iv = os.urandom(16)       # 128-bit IV (16 bytes)

    # Read and pad the file data
    with open(file_path, "rb") as f:
        plaintext = f.read()

    # Pad the data to be compatible with block size
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Encrypt the file using AES-CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Prepend IV to the ciphertext
    encrypted_data = iv + ciphertext

    # Encrypt the AES key with RSA public key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save encrypted file and encrypted AES key
    encrypted_file_path = "encrypted_file.bin"
    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_data)

    encrypted_key_path = "encrypted_key.bin"
    with open(encrypted_key_path, "wb") as f:
        f.write(encrypted_aes_key)

    return encrypted_file_path, encrypted_key_path

def decrypt_file(encrypted_file_path, encrypted_key_path, private_key_path):
    # Load User2's private key
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    # Load encrypted AES key and decrypt
    with open(encrypted_key_path, "rb") as f:
        encrypted_aes_key = f.read()
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Load encrypted file and extract IV
    with open(encrypted_file_path, "rb") as f:
        encrypted_data = f.read()
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # Decrypt the file data
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the data
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    # Save the decrypted file
    decrypted_file_path = "decrypted_file.txt"
    with open(decrypted_file_path, "wb") as f:
        f.write(decrypted_data)

    return decrypted_file_path

if __name__ == "__main__":
    # Generate User2's RSA keys if they don't exist
    if not os.path.exists("user2_private.pem") or not os.path.exists("user2_public.pem"):
        generate_rsa_keys()

    # Example usage:
    # User1 encrypts the file and key
    original_file = "original_file.txt"
    encrypted_file, encrypted_key = encrypt_file(original_file, "user2_public.pem")
    print(f"Encrypted file: {encrypted_file}, Encrypted key: {encrypted_key}")

    # User2 decrypts the key and file
    decrypted_file = decrypt_file(encrypted_file, encrypted_key, "user2_private.pem")
    print(f"Decrypted file saved as: {decrypted_file}")