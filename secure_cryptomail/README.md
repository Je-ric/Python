# 🔐 Secure CryptoMail

A simple command-line tool for **encrypting**, **decrypting**, and **emailing** files securely using AES and RSA encryption. Designed for educational or small-scale secure communication.

---

## 🚀 Purpose

Secure CryptoMail provides a secure way to:
- Encrypt files using AES (symmetric encryption)
- Save or share the AES key (optionally encrypted with RSA)
- Decrypt encrypted files using the provided key
- Send encrypted files via email with attachments

---

## 🔄 Workflow

1. **Generate RSA keys (optional)**  
   Generates a public/private RSA key pair and saves them to `_Keys/`.

2. **Encrypt a file**  
   - Encrypts a plaintext file with a randomly generated AES key.
   - Saves the encrypted file in `_Encrypted/`.
   - Stores the AES key in `_Keys/` or prints it in base64 format.

3. **Decrypt a file**  
   - Decrypts a file from `_Encrypted/` using the saved AES key from `_Keys/`.
   - Saves the decrypted file to `_Decrypted/`.

4. **Send an email**  
   - Sends an email with optional attachments (e.g., encrypted files).

---

## 🧱 Project Structure

```
secure_cryptomail/
├── run.py              # User-facing CLI launcher
├── _Encrypted/         # Encrypted output files
├── _Decrypted/         # Decrypted output files
├── _Keys/              # AES and RSA keys
├── cli/
│   └── main.py         # Command dispatcher
├── crypto/
│   ├── aes_crypto.py   # AES encryption/decryption logic
│   ├── rsa_crypto.py   # RSA key generation & encryption
│   └── key_utils.py    # Save/load RSA keys
├── emailer/
│   └── mailer.py       # Email sending logic
├── README.md
└── requirements.txt
```

---

## 🛠️ Instructions

### ✅ Prerequisites

- Python 3.8+
- Install required dependencies:
  ```bash
  pip install cryptography python-dotenv
  ```

### ▶️ Basic Usage

- **Generate RSA keys**
  ```bash
  python -m cli.main gen-keys
  ```

- **Encrypt a file**
  ```bash
  python -m cli.main encrypt myfile.txt encrypted.bin --keyout aes.key
  ```

- **Decrypt a file**
  ```bash
  python -m cli.main decrypt encrypted.bin decrypted.txt aes.key
  ```

- **Send an email with attachment**
  ```bash
  python -m cli.main send recipient@example.com "Subject" "Body" --attach encrypted.bin
  ```

---

## 📁 File Routing

- Encrypted files are saved to `_Encrypted/`
- Decrypted files are saved to `_Decrypted/`
- Keys are saved to `_Keys/`
- Only filenames should be entered when prompted, not full paths

---

## 📌 Notes

- Keys and files are not encrypted with RSA by default unless specified.
- Make sure the folders (`_Encrypted`, `_Decrypted`, `_Keys`) exist; the program will create them if missing.

---

## 📬 Credits

- AES & RSA via [cryptography](https://cryptography.io/)
- Built with ❤️ for educational use.

---