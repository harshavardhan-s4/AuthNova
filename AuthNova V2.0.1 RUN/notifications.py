import os
import json
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Use absolute paths based on module location
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
NOTIFICATIONS_FILE = os.path.join(DATA_DIR, 'notifications.json')

def ensure_notifications_file():
    os.makedirs(os.path.dirname(NOTIFICATIONS_FILE), exist_ok=True)
    if not os.path.exists(NOTIFICATIONS_FILE):
        with open(NOTIFICATIONS_FILE, 'w', encoding='utf-8') as f:
            json.dump({}, f)

def get_user_notifications(username):
    ensure_notifications_file()
    try:
        with open(NOTIFICATIONS_FILE, 'r', encoding='utf-8') as f:
            notifications = json.load(f) or {}
        return notifications.get(username, [])
    except Exception as e:
        logger.exception('Error getting notifications: %s', e)
        return []

def add_notification(username, message, type="info"):
    ensure_notifications_file()
    try:
        with open(NOTIFICATIONS_FILE, 'r', encoding='utf-8') as f:
            notifications = json.load(f) or {}
        
        if username not in notifications:
            notifications[username] = []
            
        notifications[username].append({
            'message': message,
            'type': type,
            'timestamp': datetime.utcnow().isoformat(),
            'read': False
        })
        
        with open(NOTIFICATIONS_FILE, 'w', encoding='utf-8') as f:
            json.dump(notifications, f, indent=2)
    except Exception as e:
        logger.exception('Error adding notification: %s', e)

def mark_as_read(username, timestamp):
    ensure_notifications_file()
    try:
        with open(NOTIFICATIONS_FILE, 'r', encoding='utf-8') as f:
            notifications = json.load(f) or {}
        
        if username in notifications:
            for n in notifications[username]:
                if n.get('timestamp') == timestamp:
                    n['read'] = True
                    break
            with open(NOTIFICATIONS_FILE, 'w', encoding='utf-8') as f:
                json.dump(notifications, f, indent=2)
    except Exception as e:
        logger.exception('Error marking notification as read: %s', e)