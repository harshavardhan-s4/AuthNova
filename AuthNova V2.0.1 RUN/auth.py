import os
import json
from hashlib import sha256
from datetime import datetime
import re
from argon2 import PasswordHasher, exceptions as argon2_exceptions
import logging

logger = logging.getLogger(__name__)

# Use absolute paths based on project file location
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
ph = PasswordHasher()

LEGACY_SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')

def get_users():
    """Get all users from the JSON file"""
    if not os.path.exists(USERS_FILE):
        os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump({}, f)
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            users = json.load(f) or {}
        # Normalize legacy user entries where value is a string (sha256 hash)
        changed = False
        for k, v in list(users.items()):
            if isinstance(v, str) and LEGACY_SHA256_PATTERN.match(v):
                users[k] = {'password': v, 'created_at': users.get(k + '_created_at') or datetime.utcnow().isoformat()}
                changed = True
        if changed:
            save_users(users)
        return users
    except Exception as e:
        logger.exception('Error loading users: %s', e)
        return {}

def save_users(users):
    """Save users dictionary to JSON file"""
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
        return True
    except Exception as e:
        logger.exception('Error saving users: %s', e)
        return False

def hash_password(password: str) -> str:
    """Create an Argon2 hash of password (new style)."""
    try:
        return ph.hash(password)
    except Exception:
        # fallback to sha256 if something goes wrong
        return sha256(password.encode()).hexdigest()

def sanitize_username(username: str) -> str:
    import re
    return re.sub(r'[^A-Za-z0-9_\-]', '_', username)


def register_user(username: str, password: str) -> bool:
    """Register a new user. Returns True if successful, False if username exists"""
    try:
        users = get_users()
        
        # Check if username already exists
        # Treat usernames case-insensitively
        if username.lower() in (u.lower() for u in users.keys()):
            return False
            
        username = sanitize_username(username)
        # Add new user with hashed password
        users[username] = {
            'password': hash_password(password),
            'created_at': datetime.utcnow().isoformat()
        }
        
        return save_users(users)
        
    except Exception as e:
        logger.exception('Registration error: %s', e)
        return False

def validate_login(username: str, password: str) -> bool:
    """Validate login credentials. Returns True if valid."""
    try:
        users = get_users()
        user = users.get(username)
        if not user:
            return False
        stored = user.get('password')
        # If password stored is Argon2 hash
        try:
            if isinstance(stored, str) and stored.startswith('$argon2'):
                try:
                    ok = ph.verify(stored, password)
                    if ok:
                        # rehash if parameters changed
                        try:
                            if ph.check_needs_rehash(stored):
                                users[username]['password'] = ph.hash(password)
                                save_users(users)
                        except Exception:
                            pass
                    return ok
                except argon2_exceptions.VerifyMismatchError:
                    return False
                except Exception:
                    return False
            # Old-style SHA256 string
            if isinstance(stored, str) and LEGACY_SHA256_PATTERN.match(stored):
                if stored == sha256(password.encode()).hexdigest():
                    # Upgrade hash to Argon2
                    user['password'] = hash_password(password)
                    save_users(users)
                    return True
                return False
        except Exception:
            return False
        return False
        
    except Exception as e:
        logger.exception('Login validation error: %s', e)
        return False