import os
import base64
import smtplib
import getpass
import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class CryptoSystem:
    def __init__(self):
        self.public_key = None
        self.private_key = None
    
    def generate_rsa_keys(self):
        """Generate a new RSA key pair"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key
    
    def save_keys(self, private_key_path, public_key_path):
        """Save the RSA keys to files"""
        if not self.private_key or not self.public_key:
            print("No keys to save. Generate keys first.")
            return False
        
        # Save the private key
        pem_private = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_key_path, 'wb') as f:
            f.write(pem_private)
        
        # Save the public key
        pem_public = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_path, 'wb') as f:
            f.write(pem_public)
        
        return True
    
    def load_keys(self, private_key_path=None, public_key_path=None):
        """Load RSA keys from files"""
        if private_key_path and os.path.exists(private_key_path):
            with open(private_key_path, 'rb') as f:
                private_key_data = f.read()
                self.private_key = serialization.load_pem_private_key(
                    private_key_data,
                    password=None
                )
        
        if public_key_path and os.path.exists(public_key_path):
            with open(public_key_path, 'rb') as f:
                public_key_data = f.read()
                self.public_key = serialization.load_pem_public_key(
                    public_key_data
                )
        
        return bool(self.private_key), bool(self.public_key)
    
    def load_public_key_from_data(self, public_key_data):
        """Load a public key from raw data"""
        self.public_key = serialization.load_pem_public_key(public_key_data)
        return self.public_key
    
    def encrypt_with_rsa(self, data):
        """Encrypt data using RSA public key"""
        if not self.public_key:
            raise ValueError("Public key not available")
        
        # RSA can only encrypt limited amount of data, so this is suitable for keys
        encrypted = self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted
    
    def decrypt_with_rsa(self, encrypted_data):
        """Decrypt data using RSA private key"""
        if not self.private_key:
            raise ValueError("Private key not available")
        
        decrypted = self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted
    
    def generate_aes_key(self):
        """Generate a random AES key"""
        return os.urandom(32)  # 256-bit key
    
    def encrypt_file(self, input_file, output_file, key=None):
        """Encrypt a file using AES"""
        if key is None:
            key = self.generate_aes_key()
        
        # Generate a random IV
        iv = os.urandom(16)
        
        # Create AES cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CFB(iv)
        )
        encryptor = cipher.encryptor()
        
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            # Write the IV at the beginning of the file
            f_out.write(iv)
            
            # Encrypt and write the file content
            while True:
                chunk = f_in.read(8192)
                if not chunk:
                    break
                f_out.write(encryptor.update(chunk))
            
            f_out.write(encryptor.finalize())
        
        return key
    
    def decrypt_file(self, input_file, output_file, key):
        """Decrypt a file using AES"""
        with open(input_file, 'rb') as f_in:
            # Read the IV from the beginning of the file
            iv = f_in.read(16)
            
            # Create AES cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CFB(iv)
            )
            decryptor = cipher.decryptor()
            
            with open(output_file, 'wb') as f_out:
                while True:
                    chunk = f_in.read(8192)
                    if not chunk:
                        break
                    f_out.write(decryptor.update(chunk))
                
                f_out.write(decryptor.finalize())
        
        return True

class EmailSystem:
    def __init__(self, sender_email="jericjdelacruz@gmail.com", smtp_server="smtp.gmail.com", smtp_port=587):
        self.sender_email = sender_email
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port

    def send_email(self, recipient_email, subject, body, attachments=None):
        """Send an email with optional attachments"""
        # password = getpass.getpass(f"Enter the password for {self.sender_email}: ")
        password = "qodl kpqj ioqu xtbj"  

        # Create a multipart message
        message = MIMEMultipart()
        message["From"] = self.sender_email
        message["To"] = recipient_email
        message["Subject"] = subject

        # Add body to email
        message.attach(MIMEText(body, "plain"))

        # Add attachments
        if attachments:
            for attachment_path in attachments:
                with open(attachment_path, "rb") as file:
                    attachment = MIMEApplication(file.read(), Name=os.path.basename(attachment_path))
                attachment["Content-Disposition"] = f'attachment; filename="{os.path.basename(attachment_path)}"'
                message.attach(attachment)

        # Connect to server and send email
        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.sender_email, password)
            server.sendmail(self.sender_email, recipient_email, message.as_string())
            server.quit()
            print("Email sent successfully!")
            return True
        except Exception as e:
            print(f"Error sending email: {e}")
            return False


    def send_encrypted_message(self, recipient_email, message, crypto_system):
        """Send an encrypted message using RSA"""
        if not crypto_system.public_key:
            print("Public key not available. Load or generate a key pair first.")
            return False
        
        encrypted_message = crypto_system.encrypt_with_rsa(message.encode())
        encoded_message = base64.b64encode(encrypted_message).decode()
        
        subject = "Encrypted Message"
        body = f"This is an encrypted message:\n\n{encoded_message}"
        
        return self.send_email(recipient_email, subject, body)
    
    def send_encrypted_key(self, recipient_email, aes_key, crypto_system):
        """Send an encrypted AES key using RSA"""
        if not crypto_system.public_key:
            print("Public key not available. Load or generate a key pair first.")
            return False
        
        # Encrypt the AES key with the recipient's public key
        encrypted_key = crypto_system.encrypt_with_rsa(aes_key)
        encoded_key = base64.b64encode(encrypted_key).decode()
        
        subject = "Encrypted Key"
        body = f"This is the encrypted key to decrypt the file:\n\n{encoded_key}"
        
        return self.send_email(recipient_email, subject, body)

def main():
    parser = argparse.ArgumentParser(description="Secure File Encryption and Messaging System")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Setup command
    setup_parser = subparsers.add_parser("setup", help="Generate RSA key pair")
    setup_parser.add_argument("--private", default="private_key.pem", help="Private key output file")
    setup_parser.add_argument("--public", default="public_key.pem", help="Public key output file")
    
    # Encrypt file command
    encrypt_parser = subparsers.add_parser("encrypt-file", help="Encrypt a file using AES")
    encrypt_parser.add_argument("input_file", help="File to encrypt")
    encrypt_parser.add_argument("output_file", help="Encrypted output file")
    encrypt_parser.add_argument("--key-file", help="File to save the AES key")
    
    # Decrypt file command
    decrypt_parser = subparsers.add_parser("decrypt-file", help="Decrypt a file using AES")
    decrypt_parser.add_argument("input_file", help="Encrypted file to decrypt")
    decrypt_parser.add_argument("output_file", help="Decrypted output file")
    decrypt_parser.add_argument("key_file", help="File containing the AES key")
    
    # Send encrypted file command
    send_file_parser = subparsers.add_parser("send-file", help="Send an encrypted file via email")
    send_file_parser.add_argument("recipient_email", help="Recipient email address")
    send_file_parser.add_argument("encrypted_file", help="Encrypted file to send")
    send_file_parser.add_argument("--sender-email", help="Sender email address")
    
    # Send encrypted key command
    send_key_parser = subparsers.add_parser("send-key", help="Send an encrypted AES key via email")
    send_key_parser.add_argument("recipient_email", help="Recipient email address")
    send_key_parser.add_argument("key_file", help="AES key file to encrypt and send")
    send_key_parser.add_argument("recipient_public_key", help="Recipient's public key file")
    send_key_parser.add_argument("--sender-email", help="Sender email address")
    
    # Decrypt key command
    decrypt_key_parser = subparsers.add_parser("decrypt-key", help="Decrypt an RSA encrypted key")
    decrypt_key_parser.add_argument("encrypted_key", help="Encrypted key (base64 encoded)")
    decrypt_key_parser.add_argument("output_file", help="File to save the decrypted key")
    decrypt_key_parser.add_argument("--private-key", default="private_key.pem", help="Private key file")
    
    # Send message command
    send_msg_parser = subparsers.add_parser("send-message", help="Send an encrypted message")
    send_msg_parser.add_argument("recipient_email", help="Recipient email address")
    send_msg_parser.add_argument("recipient_public_key", help="Recipient's public key file")
    send_msg_parser.add_argument("--sender-email", help="Sender email address")
    
    # Decrypt message command
    decrypt_msg_parser = subparsers.add_parser("decrypt-message", help="Decrypt an encrypted message")
    decrypt_msg_parser.add_argument("encrypted_message", help="Encrypted message (base64 encoded)")
    decrypt_msg_parser.add_argument("--private-key", default="private_key.pem", help="Private key file")
    
    args = parser.parse_args()
    
    crypto = CryptoSystem()
    
    if args.command == "setup":
        print("Generating RSA key pair...")
        crypto.generate_rsa_keys()
        if crypto.save_keys(args.private, args.public):
            print(f"Keys saved to {args.private} and {args.public}")
    
    elif args.command == "encrypt-file":
        print(f"Encrypting file {args.input_file}...")
        key = crypto.encrypt_file(args.input_file, args.output_file)
        if args.key_file:
            with open(args.key_file, 'wb') as f:
                f.write(key)
            print(f"Encryption key saved to {args.key_file}")
        else:
            encoded_key = base64.b64encode(key).decode()
            print(f"Encryption key (keep it secure!): {encoded_key}")
    
    elif args.command == "decrypt-file":
        with open(args.key_file, 'rb') as f:
            key = f.read()
        print(f"Decrypting file {args.input_file}...")
        if crypto.decrypt_file(args.input_file, args.output_file, key):
            print(f"File decrypted successfully to {args.output_file}")
    
    elif args.command == "send-file":
        email_system = EmailSystem(args.sender_email)
        print(f"Sending encrypted file to {args.recipient_email}...")
        email_system.send_email(
            args.recipient_email,
            "Encrypted File",
            "Please find the encrypted file attached. The decryption key will be sent separately.",
            [args.encrypted_file]
        )
    
    elif args.command == "send-key":
        # Load the recipient's public key
        crypto.load_keys(public_key_path=args.recipient_public_key)
        
        # Read the AES key
        with open(args.key_file, 'rb') as f:
            aes_key = f.read()
        
        email_system = EmailSystem(args.sender_email)
        print(f"Sending encrypted key to {args.recipient_email}...")
        
        # Encrypt and send the key
        encrypted_key = crypto.encrypt_with_rsa(aes_key)
        encoded_key = base64.b64encode(encrypted_key).decode()
        
        email_system.send_email(
            args.recipient_email,
            "Encrypted Key",
            f"This is the encrypted key to decrypt the file:\n\n{encoded_key}"
        )
    
    elif args.command == "decrypt-key":
        # Load private key
        crypto.load_keys(private_key_path=args.private_key)
        
        # Decrypt the key
        encrypted_key = base64.b64decode(args.encrypted_key)
        decrypted_key = crypto.decrypt_with_rsa(encrypted_key)
        
        # Save the decrypted key
        with open(args.output_file, 'wb') as f:
            f.write(decrypted_key)
        
        print(f"Key decrypted successfully and saved to {args.output_file}")
    
    elif args.command == "send-message":
        # Load the recipient's public key
        crypto.load_keys(public_key_path=args.recipient_public_key)
        
        # Get the message
        message = input("Enter the message to encrypt: ")
        
        email_system = EmailSystem(args.sender_email)
        print(f"Sending encrypted message to {args.recipient_email}...")
        email_system.send_encrypted_message(args.recipient_email, message, crypto)
    
    elif args.command == "decrypt-message":
        # Load private key
        crypto.load_keys(private_key_path=args.private_key)
        
        # Decrypt the message
        encrypted_message = base64.b64decode(args.encrypted_message)
        decrypted_message = crypto.decrypt_with_rsa(encrypted_message)
        
        print("Decrypted message:")
        print(decrypted_message.decode())
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()