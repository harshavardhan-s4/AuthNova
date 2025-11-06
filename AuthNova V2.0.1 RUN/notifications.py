import os
import json
from datetime import datetime

NOTIFICATIONS_FILE = 'data/notifications.json'

def ensure_notifications_file():
    os.makedirs('data', exist_ok=True)
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
        print(f"Error getting notifications: {e}")
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
        print(f"Error adding notification: {e}")

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
        print(f"Error marking notification as read: {e}")