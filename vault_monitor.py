from datetime import datetime
from breach_check.email import check_email_breach
from breach_check.password import check_password_breach
from vault import get_vault

def check_vault_entries(username: str):
    """
    Scans vault entries for a user and returns list of breached entries:
    [
      {
        'label': str,
        'email': str or None,
        'email_breaches': int,
        'password_breached': bool,
        'password_count': int or None,
        'timestamp': ISO str
      }, ...
    ]
    """
    entries = get_vault(username) or []
    breached = []
    for e in entries:
        label = e.get('label')
        email = e.get('email')
        pwd = e.get('password')
        email_count = 0
        pwd_count = None

        # check email breaches
        if email:
            try:
                email_result = check_email_breach(email)
                if isinstance(email_result, list):
                    email_count = len(email_result)
                elif isinstance(email_result, int):
                    email_count = email_result
                else:
                    # unknown type: coerce to 0
                    email_count = 0
            except Exception:
                email_count = 0

        # check password breaches (returns count or None)
        if pwd:
            try:
                pwd_count = check_password_breach(pwd)
            except Exception:
                pwd_count = None

        password_breached = bool(pwd_count and pwd_count > 0)
        if (email_count and email_count > 0) or password_breached:
            breached.append({
                'label': label,
                'email': email,
                'email_breaches': email_count or 0,
                'password_breached': password_breached,
                'password_count': pwd_count,
                'timestamp': datetime.utcnow().isoformat()
            })
    return breached