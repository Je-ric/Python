import os
import argparse
import datetime
from vault import encrypt_file, decrypt_file

LOG_FILE = 'logs/vault_log.txt'

def log(action, filename, error=None):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, 'a') as f:
        timestamp = datetime.datetime.now()
        if error:
            f.write(f"{timestamp} - ERROR during {action} - {filename} - {error}\n")
        else:
            f.write(f"{timestamp} - {action} - {filename}\n")


def process_folder(folder, mode):
    try:
        if not os.path.exists(folder):
            raise FileNotFoundError(f"Folder '{folder}' does not exist.")
        
        for filename in os.listdir(folder):
            path = os.path.join(folder, filename)
            if os.path.isfile(path):
                try:
                    if mode == 'encrypt':
                        out = path + '.enc'
                        encrypt_file(path, out)
                        log('encrypt', filename)
                    elif mode == 'decrypt' and filename.endswith('.enc'):
                        out = path[:-4]
                        decrypt_file(path, out)
                        log('decrypt', filename)
                except Exception as e:
                    log(mode, filename, error=str(e))
    except Exception as e:
        log('process_folder', folder, error=str(e))
        raise ValueError(f"An error occurred: {e}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Batch encrypt/decrypt files in a folder')
    parser.add_argument('folder', help='Folder path')
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help='Operation mode')
    args = parser.parse_args()
    process_folder(args.folder, args.mode)