import os
import json
from hashlib import sha256
from datetime import datetime

USERS_FILE = 'data/users.json'

def get_users():
    """Get all users from the JSON file"""
    if not os.path.exists(USERS_FILE):
        os.makedirs('data', exist_ok=True)
        with open(USERS_FILE, 'w') as f:
            json.dump({}, f)
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading users: {e}")
        return {}

def save_users(users):
    """Save users dictionary to JSON file"""
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving users: {e}")
        return False

def hash_password(password: str) -> str:
    """Create SHA256 hash of password"""
    return sha256(password.encode()).hexdigest()

def register_user(username: str, password: str) -> bool:
    """Register a new user. Returns True if successful, False if username exists"""
    try:
        users = get_users()
        
        # Check if username already exists
        if username in users:
            return False
            
        # Add new user with hashed password
        users[username] = {
            'password': hash_password(password),
            'created_at': datetime.utcnow().isoformat()
        }
        
        return save_users(users)
        
    except Exception as e:
        print(f"Registration error: {e}")
        return False

def validate_login(username: str, password: str) -> bool:
    """Validate login credentials. Returns True if valid."""
    try:
        users = get_users()
        user = users.get(username)
        
        if not user:
            return False
            
        return user.get('password') == hash_password(password)
        
    except Exception as e:
        print(f"Login validation error: {e}")
        return False