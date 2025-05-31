import os
import argparse
import datetime
import getpass
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from auth import register_user, authenticate_user
from vault import encrypt_file, decrypt_file

LOG_FILE = 'logs/vault_log.txt'
ENC_DIR = 'encrypted_files'

def log(action, filename, user=None):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    entry = f"{datetime.datetime.now()} - {action} - {filename}"
    if user:
        entry += f" - user: {user}"
    entry += "\n"
    with open(LOG_FILE, 'a') as f:
        f.write(entry)

def run_cli():
    print("=== Secure File Vault CLI ===")
    user = input("Username: ")
    pwd = getpass.getpass()
    if not authenticate_user(user, pwd):
        print("Invalid credentials")
        return
    log('login', user, user)
    while True:
        print("\nOptions:\n1. Encrypt File\n2. Decrypt File\n3. Batch Process Folder\n4. Logout\n5. Exit GUI Mode")
        choice = input("Choose an option: ")
        if choice == '1':
            path = input("Path to file: ")
            if os.path.isfile(path):
                os.makedirs(ENC_DIR, exist_ok=True)
                out = os.path.join(ENC_DIR, os.path.basename(path) + '.enc')
                encrypt_file(path, out)
                log('encrypt', os.path.basename(path), user)
                print("File encrypted:", out)
            else:
                print("Invalid file path.")
        elif choice == '2':
            path = input(f"Path to .enc file (default folder {ENC_DIR}): ")
            if not os.path.isabs(path):
                path = os.path.join(ENC_DIR, path)
            if os.path.isfile(path) and path.endswith('.enc'):
                out = path[:-4]
                decrypt_file(path, out)
                log('decrypt', os.path.basename(path), user)
                print("File decrypted:", out)
            else:
                print("Invalid .enc file path.")
        elif choice == '3':
            folder = input("Folder path: ")
            mode = input("Mode (encrypt/decrypt): ")
            if mode in ['encrypt', 'decrypt'] and os.path.isdir(folder):
                from batch_processor import process_folder
                process_folder(folder, mode)
                print("Batch processing complete.")
            else:
                print("Invalid input.")
        elif choice == '4':
            log('logout', user, user)
            print("Logged out.")
            break
        elif choice == '5':
            break
        else:
            print("Invalid choice.")

class LoginWindow:
    def __init__(self, master):
        self.master = master
        master.title("JHR Project - Login/Register")
        # dynamically fit screen
        width = master.winfo_screenwidth()
        height = master.winfo_screenheight()
        master.geometry(f"{width}x{height}")
        master.resizable(False, False)
        master.configure(bg="#213448")

        style = ttk.Style()
        style.theme_use('clam') 
        style.configure("Custom.TFrame", background="#213448", foreground="#fff7d6")
        style.configure("CustomTitle.TLabel", background="#213448", foreground="#fff7d6", font=('Segoe UI', 30, 'bold'))
        style.configure("Custom.TLabel", background="#213448", foreground="#fff7d6", font=('Segoe UI', 16))
        style.configure("Custom.TEntry", fieldbackground="#213448", foreground="#fff7d6")
        style.configure("Custom.TButton", background="#fff7d6", foreground="#213448", font=('Segoe UI', 16), padding=6)

        frame = ttk.Frame(master, padding=50, style="Custom.TFrame")
        frame.place(relx=0.5, rely=0.5, anchor='center')

        title = ttk.Label(frame, text="Secure File Vault", style="CustomTitle.TLabel")
        title.grid(row=0, column=0, columnspan=2, pady=(0,20))

        ttk.Label(frame, text="Username:", style="Custom.TLabel").grid(row=1, column=0, sticky='w', pady=5)
        ttk.Label(frame, text="Password:", style="Custom.TLabel").grid(row=2, column=0, sticky='w', pady=5)
        self.username = ttk.Entry(frame, style="Custom.TEntry", font=('Segoe UI', 14))
        self.password = ttk.Entry(frame, show='*', style="Custom.TEntry", font=('Segoe UI', 14))
        self.username.grid(row=1, column=1, pady=5, padx=10)
        self.password.grid(row=2, column=1, pady=5, padx=10)

        login_btn = ttk.Button(frame, text="Login", command=self.login, style="Custom.TButton" )
        register_btn = ttk.Button(frame, text="Register", command=self.register, style="Custom.TButton")
        login_btn.grid(row=3, column=0, pady=20, padx=5)
        register_btn.grid(row=3, column=1, pady=20, padx=5)

    def login(self):
        user = self.username.get()
        pwd = self.password.get()
        try:
            if authenticate_user(user, pwd):
                log('login', user, user)
                self.master.destroy()
                root = tk.Tk()
                VaultWindow(root, user)
                root.mainloop()
        except ValueError as ve:
            messagebox.showerror("Login Failed", str(ve))

    def register(self):
        user = self.username.get()
        pwd = self.password.get()
        try:
            register_user(user, pwd)
            messagebox.showinfo("Success", "User registered")
            log('register', user, user)
        except Exception as e:
            messagebox.showerror("Error", str(e))

class VaultWindow:
    def __init__(self, master, user):
        self.master = master
        self.user = user
        master.title(f"JHR Project - {user} Secure Vault")
        width = master.winfo_screenwidth()
        height = master.winfo_screenheight()
        master.geometry(f"{width}x{height}")
        master.resizable(False, False)
        master.configure(bg="#3c4856")

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Custom.TFrame", background="#213448", foreground="#fff7d6")
        style.configure("Custom.TButton", background="#fff7d6", foreground="#213448", font=('Segoe UI', 10, 'bold'))

        style.configure("Custom.TLabel", background="#213448", foreground="#fff7d6", font=('Segoe UI', 16))

        style.configure("Custom.TLabelframe", background="#3c4856", foreground="#fff7d6", font=('Segoe UI', 16, 'bold'), padding=10)
        style.configure("Custom.TLabelframe.Label", background="#3c4856",foreground="#fff7d6",font=('Segoe UI', 16, 'bold'))

        style.configure("Custom.Treeview", background="#3c4856", foreground="#fff7d6", rowheight=25, fieldbackground="#3c4856", font=('Segoe UI', 12))
        style.configure("Custom.Treeview.Heading", background="#4a4a4a", foreground="#fff7d6", font=('Segoe UI', 14, 'bold'))

        toolbar = ttk.Frame(master, padding=10, style="Custom.TFrame")
        toolbar.pack(fill='x')
        actions = [("Encrypt File", self.encrypt_file),
                   ("Decrypt File", self.decrypt_file),
                   ("Batch Process Folder", self.batch_folder),
                   ("Refresh List", self.refresh_lists),
                   ("Logout", self.logout)]
        for txt, cmd in actions:
            btn = ttk.Button(toolbar, text=txt, command=cmd, style="Custom.TButton")
            btn.pack(side='left', padx=5)

        spacer = ttk.Frame(toolbar)
        spacer.pack(side='left', expand=True)

        # Right-side element (example: label or button)
        user_label = ttk.Label(toolbar, text=f"Logged in as: {user}", style="Custom.TLabel")
        user_label.pack(side='right')

        paned = ttk.Panedwindow(master, orient='horizontal')
        paned.pack(fill='both', expand=True, padx=20, pady=10)

        enc_frame = ttk.Labelframe(paned, text="Encrypted Files", padding=10, style="Custom.TLabelframe")
        dec_frame = ttk.Labelframe(paned, text="Decrypted Files", padding=10, style="Custom.TLabelframe")
        paned.add(enc_frame, weight=1)
        paned.add(dec_frame, weight=1)

        self.enc_tree = ttk.Treeview(enc_frame, columns=('filename',), show='headings', style="Custom.Treeview")
        self.enc_tree.heading('filename', text='Filename')
        enc_scroll = ttk.Scrollbar(enc_frame, orient='vertical', command=self.enc_tree.yview, style="Vertical.TScrollbar")
        self.enc_tree.configure(yscrollcommand=enc_scroll.set)
        self.enc_tree.pack(side='left', fill='both', expand=True)
        enc_scroll.pack(side='right', fill='y')

        self.dec_tree = ttk.Treeview(dec_frame, columns=('filename',), show='headings', style="Custom.Treeview")
        self.dec_tree.heading('filename', text='Filename')
        dec_scroll = ttk.Scrollbar(dec_frame, orient='vertical', command=self.dec_tree.yview)
        self.dec_tree.configure(yscrollcommand=dec_scroll.set)
        self.dec_tree.pack(side='left', fill='both', expand=True)
        dec_scroll.pack(side='right', fill='y')

        self.refresh_lists()

    def refresh_lists(self):
        self.enc_tree.delete(*self.enc_tree.get_children())
        self.dec_tree.delete(*self.dec_tree.get_children())
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                for line in f:
                    parts = line.strip().split(' - ')
                    if len(parts) >= 3:
                        action, fname = parts[1], parts[2]
                        if action == 'encrypt':
                            self.enc_tree.insert('', 'end', values=(fname,))
                        elif action == 'decrypt':
                            self.dec_tree.insert('', 'end', values=(fname,))

    def encrypt_file(self):
        try:
            path = filedialog.askopenfilename()
            if path:
                os.makedirs(ENC_DIR, exist_ok=True)
                out = os.path.join(ENC_DIR, os.path.basename(path) + '.enc')
                encrypt_file(path, out)
                log('encrypt', os.path.basename(path), self.user)
                messagebox.showinfo("Success", f"File encrypted: {out}")
                self.refresh_lists()
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_file(self):
        try:
            path = filedialog.askopenfilename(initialdir=ENC_DIR)
            if path and path.endswith('.enc'):
                out = path[:-4]
                decrypt_file(path, out)
                log('decrypt', os.path.basename(path), self.user)
                messagebox.showinfo("Success", f"File decrypted: {out}")
                self.refresh_lists()
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def batch_folder(self):
        try:
            folder = filedialog.askdirectory()
            if folder:
                mode = messagebox.askquestion("Mode", "Encrypt files? (Yes=Encrypt, No=Decrypt)")
                action = 'encrypt' if mode == 'yes' else 'decrypt'
                from batch_processor import process_folder
                process_folder(folder, action)
                log(f"{action}_batch", os.path.basename(folder), self.user)
                messagebox.showinfo("Success", "Batch processing complete")
                self.refresh_lists()
        except Exception as e:
            messagebox.showerror("Batch Error", str(e))

    def logout(self):
        log('logout', self.user, self.user)
        self.master.destroy()
        root = tk.Tk()
        LoginWindow(root)
        root.mainloop()


def main():
    parser = argparse.ArgumentParser(description='Secure File Vault')
    parser.add_argument('--cli', action='store_true', help='Run in CLI mode')
    args = parser.parse_args()
    if args.cli:
        run_cli()
    else:
        root = tk.Tk()
        LoginWindow(root)
        root.mainloop()

if __name__ == '__main__':
    main()
