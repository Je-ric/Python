import argparse
import base64
import os
from crypto import rsa_crypto, aes_crypto, key_utils
from emailer import mailer

ENCRYPT_DIR = "_Encrypted"
KEYS_DIR = "_Keys"
DECRYPT_DIR = "_Decrypted"

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("gen-keys")

    encrypt = sub.add_parser("encrypt")
    encrypt.add_argument("infile")
    encrypt.add_argument("outfile")
    encrypt.add_argument("--keyout")

    decrypt = sub.add_parser("decrypt")
    decrypt.add_argument("infile")
    decrypt.add_argument("outfile")
    decrypt.add_argument("keyfile")

    send = sub.add_parser("send")
    send.add_argument("recipient")
    send.add_argument("subject")
    send.add_argument("body")
    send.add_argument("--attach", nargs="*")

    args = parser.parse_args()

    if args.cmd == "gen-keys":
        priv, pub = rsa_crypto.generate_key_pair()
        ensure_dir(KEYS_DIR)
        key_utils.save_private_key(priv, os.path.join(KEYS_DIR, "private.pem"))
        key_utils.save_public_key(pub, os.path.join(KEYS_DIR, "public.pem"))
        print(f"Keys saved to {KEYS_DIR}/private.pem and {KEYS_DIR}/public.pem.")

    elif args.cmd == "encrypt":
        ensure_dir(ENCRYPT_DIR) 
        ensure_dir(KEYS_DIR)

        outpath = os.path.join(ENCRYPT_DIR, os.path.basename(args.outfile)) 
        # This is where the encrypted file will be saved (inside the encrypted folder)

        key = aes_crypto.generate_aes_key()
        aes_crypto.encrypt_file(args.infile, outpath, key)

        if args.keyout:
            key_filename = os.path.basename(args.keyout)
            keypath = os.path.join(KEYS_DIR, key_filename)
            with open(keypath, "wb") as f:
                f.write(key)
            print(f"Encryption key saved to {keypath}")
        else:
            print("Key (base64):", base64.b64encode(key).decode())
        print(f"File encrypted and saved to {outpath}")

    elif args.cmd == "decrypt":
        ensure_dir(KEYS_DIR)
        ensure_dir(ENCRYPT_DIR)
        ensure_dir(DECRYPT_DIR)  

        # Look for the encrypted file inside the encrypted folder
        input_path = os.path.join(ENCRYPT_DIR, os.path.basename(args.infile))

        # Look for the AES key file inside the keys folder
        key_filename = os.path.basename(args.keyfile)
        keypath = os.path.join(KEYS_DIR, key_filename)

        if not os.path.isfile(input_path):
            print(f"Error: Encrypted file '{input_path}' does not exist.")
            return

        if not os.path.isfile(keypath):
            print(f"Error: Key file '{keypath}' does not exist.")
            return

        with open(keypath, "rb") as f:
            key = f.read()

        # This is where the decrypted file will be saved (inside the decrypted folder)
        output_path = os.path.join(DECRYPT_DIR, os.path.basename(args.outfile)) 
        aes_crypto.decrypt_file(input_path, output_path, key)
        print(f"Decryption complete. File saved to {output_path}")

    elif args.cmd == "send":
        mailer.send_email(args.recipient, args.subject, args.body, args.attach)
        print("Email sent.")

if __name__ == "__main__":
    main()
