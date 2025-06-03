import os
import base64
import smtplib
import getpass
import sys
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
    def __init__(self, sender_email=None, smtp_server="smtp.gmail.com", smtp_port=587):
        self.sender_email = sender_email
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
    
    def send_email(self, recipient_email, subject, body, attachments=None):
        """Send an email with optional attachments"""
        if not self.sender_email:
            self.sender_email = input("Enter your email address: ")
        
        password = getpass.getpass("Enter your email password/app password: ")
        
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
            text = message.as_string()
            server.sendmail(self.sender_email, recipient_email, text)
            server.quit()
            print("Email sent successfully!")
            return True
        except Exception as e:
            print(f"Error sending email: {e}")
            return False
    
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

def generate_keys():
    user_type = input("Are you User1 or User2? (1/2): ")
    if user_type == "1":
        private_key = "user1_private.pem"
        public_key = "user1_public.pem"
    elif user_type == "2":
        private_key = "user2_private.pem"
        public_key = "user2_public.pem"
    else:
        print("Invalid option. Defaulting to User1.")
        private_key = "user1_private.pem"
        public_key = "user1_public.pem"
    
    crypto = CryptoSystem()
    print(f"Generating RSA key pair for User{user_type}...")
    crypto.generate_rsa_keys()
    
    if crypto.save_keys(private_key, public_key):
        print(f"Keys saved to {private_key} and {public_key}")
        print("\nIMPORTANT: Share your public key with the other user, but keep your private key secure!")
        return True
    else:
        print("Failed to generate keys.")
        return False

def send_file():
    print("\n--- Send Encrypted File and Key ---")
    
    # Check if we're User1 or User2
    user_type = input("Are you User1 or User2? (1/2): ")
    
    if user_type == "1":
        sender_private_key = "user1_private.pem"
        recipient_public_key = "user2_public.pem"
    elif user_type == "2":
        sender_private_key = "user2_private.pem"
        recipient_public_key = "user1_public.pem"
    else:
        print("Invalid option. Defaulting to User1.")
        sender_private_key = "user1_private.pem"
        recipient_public_key = "user1_public.pem"
    
    # Check if recipient's public key exists
    if not os.path.exists(recipient_public_key):
        print(f"Error: {recipient_public_key} not found.")
        print("Make sure you have the recipient's public key in the current directory.")
        return False
    
    # Get file to encrypt
    input_file = input("Enter the path to the file you want to encrypt and send: ")
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found.")
        return False
    
    # Setup the encrypted file name
    file_base = os.path.basename(input_file)
    encrypted_file = f"encrypted_{file_base}"
    key_file = f"aes_key_{file_base}.bin"
    
    # Encrypt the file
    crypto = CryptoSystem()
    print(f"Encrypting file {input_file}...")
    key = crypto.encrypt_file(input_file, encrypted_file)
    
    # Save the key
    with open(key_file, 'wb') as f:
        f.write(key)
    print(f"Encryption key saved to {key_file}")
    
    # Get recipient's email
    recipient_email = input("Enter recipient's email address: ")
    
    # Send the encrypted file
    email_system = EmailSystem()
    print(f"Sending encrypted file to {recipient_email}...")
    if not email_system.send_email(
        recipient_email,
        "Encrypted File",
        "Please find the encrypted file attached. The decryption key will be sent separately.",
        [encrypted_file]
    ):
        print("Failed to send encrypted file.")
        return False
    
    # Load recipient's public key for encrypting the AES key
    crypto = CryptoSystem()
    crypto.load_keys(public_key_path=recipient_public_key)
    
    # Read the AES key
    with open(key_file, 'rb') as f:
        aes_key = f.read()
    
    # Encrypt and send the key
    print(f"Encrypting and sending AES key to {recipient_email} using their public key...")
    encrypted_key = crypto.encrypt_with_rsa(aes_key)
    encoded_key = base64.b64encode(encrypted_key).decode()
    
    if not email_system.send_email(
        recipient_email,
        "Encrypted Key",
        f"This is the encrypted key to decrypt the file:\n\n{encoded_key}"
    ):
        print("Failed to send encrypted key.")
        return False
    
    print("\nFile and key sent successfully!")
    print(f"The recipient will need to decrypt the key using their private key ({recipient_public_key.replace('public', 'private')})")
    return True

def decrypt_file():
    print("\n--- Decrypt File ---")
    
    # Check if we're User1 or User2
    user_type = input("Are you User1 or User2? (1/2): ")
    
    if user_type == "1":
        private_key_path = "user1_private.pem"
    elif user_type == "2":
        private_key_path = "user2_private.pem"
    else:
        print("Invalid option. Defaulting to User1.")
        private_key_path = "user1_private.pem"
    
    # Check if private key exists
    if not os.path.exists(private_key_path):
        print(f"Error: Private key file {private_key_path} not found.")
        print("You need your private key to decrypt files.")
        return False
    
    # Load the private key
    crypto = CryptoSystem()
    crypto.load_keys(private_key_path=private_key_path)
    
    # Get encrypted file
    encrypted_file = input("Enter the path to the encrypted file: ")
    if not os.path.exists(encrypted_file):
        print(f"Error: File '{encrypted_file}' not found.")
        return False
    
    # Get the encrypted key
    encrypted_key = input("Enter the encrypted key from the email: ")
    
    try:
        # Decrypt the key
        encrypted_key_bytes = base64.b64decode(encrypted_key)
        decrypted_key = crypto.decrypt_with_rsa(encrypted_key_bytes)
        
        # Setup the decrypted file name
        file_base = os.path.basename(encrypted_file)
        if file_base.startswith("encrypted_"):
            file_base = file_base[10:]  # Remove the 'encrypted_' prefix
        decrypted_file = f"decrypted_{file_base}"
        
        # Decrypt the file
        print(f"Decrypting file {encrypted_file}...")
        if crypto.decrypt_file(encrypted_file, decrypted_file, decrypted_key):
            print(f"File decrypted successfully! Saved as {decrypted_file}")
            
            # Ask if the user wants to send the decrypted file back
            send_back = input("Do you want to send the decrypted file back to the sender? (y/n): ")
            if send_back.lower() == 'y':
                recipient_email = input("Enter the sender's email address: ")
                email_system = EmailSystem()
                print(f"Sending decrypted file to {recipient_email}...")
                if email_system.send_email(
                    recipient_email,
                    "Decrypted File",
                    "Here is the decrypted file you sent me.",
                    [decrypted_file]
                ):
                    print("Decrypted file sent successfully!")
                else:
                    print("Failed to send decrypted file.")
            
            return True
        else:
            print("Failed to decrypt file.")
            return False
            
    except Exception as e:
        print(f"Error during decryption: {e}")
        print("Make sure you're using the correct private key and encrypted key.")
        return False

def main_menu():
    while True:
        print("\n=== Secure File Encryption and Messaging System ===")
        print("\n1. Generate Keys")
        print("2. Send File via Email")
        print("3. Decrypt File")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == "1":
            generate_keys()
        elif choice == "2":
            send_file()
        elif choice == "3":
            decrypt_file()
        elif choice == "4":
            print("Exiting program. Goodbye!")
            sys.exit(0)
        else:
            print("Invalid option. Please try again.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main_menu()