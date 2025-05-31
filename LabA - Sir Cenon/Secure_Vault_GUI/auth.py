import hashlib
import json
import os

USER_DB = 'users.json'


def load_users():
    if not os.path.exists(USER_DB):
        return {}
    try:
        with open(USER_DB, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        raise ValueError(f"Failed to load user database: {e}")
        return {}


def save_users(users):
    try:
        with open(USER_DB, 'w') as f:
            json.dump(users, f, indent=4)
    except IOError as e:
        raise ValueError(f"Failed to save user database: {e}")
        print()


def register_user(username, password):
    if not username or not password:
        raise ValueError("Username and password cannot be empty.")

    users = load_users()
    if username in users:
        raise ValueError("Username already exists.")

    hashed = hashlib.sha256(password.encode()).hexdigest()
    users[username] = hashed
    save_users(users)
    print(f"[Success] User '{username}' registered.")


def authenticate_user(username, password):
    users = load_users()
    if username not in users:
        raise ValueError("Username not found.")
        return False

    hashed = hashlib.sha256(password.encode()).hexdigest()
    if users[username] != hashed:
        raise ValueError("Incorrect password.")
        return False

    print(f"[Success] User '{username}' authenticated.")
    return True