import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_aes_key():
    return os.urandom(32)

def encrypt_file(input_path, output_path, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
        f_out.write(iv)
        while chunk := f_in.read(8192):
            f_out.write(encryptor.update(chunk))
        f_out.write(encryptor.finalize())

def decrypt_file(input_path, output_path, key):
    with open(input_path, "rb") as f_in:
        iv = f_in.read(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()

        with open(output_path, "wb") as f_out:
            while chunk := f_in.read(8192):
                f_out.write(decryptor.update(chunk))
            f_out.write(decryptor.finalize())