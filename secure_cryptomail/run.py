import os
import sys

def main():
    print("Select an option:")
    print("1. Generate RSA keys")
    print("2. Encrypt a file")
    print("3. Decrypt a file")
    print("4. Send an email")
    choice = input("Enter number: ")

    if choice == "1":
        os.system("python -m cli.main gen-keys")

    elif choice == "2":
        infile = input("File to encrypt: ")
        outfile = input("Output file name: ")
        keyout = input("Save AES key to (filename only, e.g. aes.key): ")
        os.system(f"python -m cli.main encrypt {infile} {outfile} --keyout {keyout}")

    elif choice == "3":
        infile = input("Encrypted file: ")
        outfile = input("Decrypted output file: ")
        keyfile = input("AES key file (filename only, inside '_Keys' folder): ")
        os.system(f"python -m cli.main decrypt {infile} {outfile} {keyfile}")

    elif choice == "4":
        recipient = input("Recipient email: ")
        subject = input("Subject: ")
        body = input("Body: ")
        attachment = input("Attachment file (optional): ")
        attach_arg = f"--attach {attachment}" if attachment else ""
        os.system(f"python -m cli.main send {recipient} \"{subject}\" \"{body}\" {attach_arg}")

    else:
        print("Invalid option")

if __name__ == "__main__":
    main()
