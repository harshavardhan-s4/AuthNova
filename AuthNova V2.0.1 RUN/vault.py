import os
import json
from datetime import datetime

VAULT_DIR = 'data/vaults'
os.makedirs(VAULT_DIR, exist_ok=True)

def _vault_path(username: str) -> str:
    safe = username.replace('/', '_')
    return os.path.join(VAULT_DIR, f"{safe}.json")

def get_vault(username: str):
    """Return list of entries for user. Each entry: {label, username, password, email, created_at}"""
    path = _vault_path(username)
    if not os.path.exists(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # Ensure we always return a list
            if isinstance(data, list):
                return data
            # support older shape where vault may be stored as dict
            if isinstance(data, dict):
                return data.get('entries', []) or []
            return []
    except Exception:
        return []

def save_vault(username: str, entries):
    path = _vault_path(username)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=2)

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