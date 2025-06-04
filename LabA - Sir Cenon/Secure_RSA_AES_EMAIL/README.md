# 🔐 Secure RSA-AES Email System

## 📄 What is this?

This project is a **Secure File Encryption and Messaging System** that allows users to encrypt files using AES, encrypt the AES key with RSA, and send both the encrypted file and key via email. It is designed for secure file transfer between two users, ensuring that only the intended recipient can decrypt and access the file contents.

---

## 🎯 Purpose

- **Confidentiality:** Protect sensitive files by encrypting them before sending.
- **Key Security:** Use RSA public/private key pairs to securely share AES keys.
- **Convenience:** Send encrypted files and keys directly via email.
- **Educational:** Demonstrates hybrid encryption (AES for data, RSA for key exchange) and secure email sending in Python.

---

## 🛠️ How to Run

### 1. **Requirements**

- Python 3.8+
- Install dependencies:
  ```bash
  pip install cryptography
  ```

### 2. **Files**

- `project.py` — Main program file
- `members.txt` — Project members
- `demo.mp4` — Demo video (optional)

### 3. **Usage**

1. **Start the Program**
   ```bash
   python project.py
   ```

2. **Main Menu Options**
   - **1. Generate Keys:**  
     Generates RSA public/private key pairs for User1 and User2.
   - **2. Send File via Email:**  
     - Choose User1 or User2 (determines which keys to use).
     - Enter the path to the file you want to encrypt and send.
     - Enter the recipient's email address.
     - The program will:
       - Encrypt the file with AES.
       - Encrypt the AES key with the recipient's RSA public key.
       - Email the encrypted file as an attachment.
       - Email the encrypted AES key as a message.
   - **3. Decrypt File:**  
     - Enter the encrypted file and key paths.
     - Decrypts the AES key with your private RSA key, then decrypts the file.
   - **4. Exit:**  
     Exits the program.

3. **Key Files**
   - Keys are saved as `user1_private.pem`, `user1_public.pem`, `user2_private.pem`, `user2_public.pem`.

4. **Email Sending**
   - The program will prompt for email credentials if needed.
   - Make sure you have access to the recipient's public key file.

---

## 📦 Example Workflow

1. **User1** generates keys.
2. **User1** encrypts and sends a file to **User2**.
3. **User2** receives the encrypted file and encrypted key via email.
4. **User2** uses their private key to decrypt the AES key, then decrypts the file.

---

## 👥 Members

See `members.txt` for the list of contributors.

---

## 📺 Demo

See `demo.mp4` for a demonstration of the system in action.

---

*For educational use. Always verify security for production systems!*