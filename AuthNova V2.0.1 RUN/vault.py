import os
import json
from datetime import datetime
import base64
from cryptography.fernet import Fernet, InvalidToken

# Use absolute paths based on module location
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
VAULT_DIR = os.path.join(DATA_DIR, 'vaults')
os.makedirs(VAULT_DIR, exist_ok=True)

def _vault_path(username: str) -> str:
    # sanitize usernames to only allow alphanumeric, dash and underscore
    import re
    safe = re.sub(r'[^A-Za-z0-9_\-]', '_', username)
    return os.path.join(VAULT_DIR, f"{safe}.json")


def _get_fernet():
    key = os.environ.get('VAULT_MASTER_KEY')
    if not key:
        return None
    # If key is not 32-byte base64, try to convert
    try:
        return Fernet(key)
    except Exception:
        # try to generate from arbitrary passphrase (not recommended)
        try:
            k = base64.urlsafe_b64encode(key.encode('utf-8')[:32].ljust(32, b'\0'))
            return Fernet(k)
        except Exception:
            return None

def get_vault(username: str):
    """Return list of entries for user. Each entry: {label, username, password, email, created_at}"""
    path = _vault_path(username)
    if not os.path.exists(path):
        return []
    fernet = _get_fernet()
    try:
        # Try to parse as plaintext JSON first (legacy)
        with open(path, 'r', encoding='utf-8') as f:
            text = f.read()
        try:
            data = json.loads(text)
            # Normal plain JSON format
            if isinstance(data, list):
                # If encryption configured, re-save encrypted form
                if fernet:
                    save_vault(username, data)
                return data
            if isinstance(data, dict):
                entries = data.get('entries', []) or []
                if fernet:
                    save_vault(username, entries)
                return entries
        except Exception:
            # Not parseable JSON; try decrypting using Fernet
            if fernet:
                try:
                    dec = fernet.decrypt(text.encode('utf-8'))
                    data = json.loads(dec.decode('utf-8'))
                    if isinstance(data, list):
                        return data
                    if isinstance(data, dict):
                        return data.get('entries', []) or []
                except InvalidToken:
                    return []
                except Exception:
                    return []
        return []
    except Exception:
        return []

def save_vault(username: str, entries):
    path = _vault_path(username)
    fernet = _get_fernet()
    payload = json.dumps(entries, indent=2)
    try:
        if fernet:
            token = fernet.encrypt(payload.encode('utf-8'))
            with open(path, 'w', encoding='utf-8') as f:
                f.write(token.decode('utf-8'))
        else:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(entries, f, indent=2)
    except Exception:
        # fail silently; the caller will typically log if needed
        return

def add_entry(username: str, label: str, entry_username: str, password: str, email: str = None):
    entries = get_vault(username)
    # replace existing entry with same label (unique labels)
    entries = [e for e in entries if e.get('label') != label]
    entries.append({
        'label': label,
        'username': entry_username,
        'password': password,
        'email': email,
        'created_at': datetime.utcnow().isoformat()
    })
    save_vault(username, entries)

def delete_entry(username: str, label: str):
    entries = get_vault(username)
    new = [e for e in entries if e.get('label') != label]
    save_vault(username, new)