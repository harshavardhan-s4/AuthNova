import json
import os
from datetime import datetime
import re
import logging

logger = logging.getLogger(__name__)

# Use absolute path for users.json
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
DATA_DIR = os.path.join(ROOT_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
LEGACY_SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')

if not os.path.exists(USERS_FILE):
    logger.warning('No users.json found at %s', USERS_FILE)
    exit(1)

with open(USERS_FILE, 'r') as f:
    users = json.load(f) or {}

changed = False
for k, v in list(users.items()):
    if isinstance(v, str) and LEGACY_SHA256_PATTERN.match(v):
        users[k] = {
            'password': v,
            'created_at': datetime.utcnow().isoformat()
        }
        changed = True

if changed:
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2)
    logger.info('Migrated users to structured format')
else:
    logger.info('No migration needed')
