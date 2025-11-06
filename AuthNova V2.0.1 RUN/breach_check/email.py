import requests
from urllib.parse import quote

def check_email_breach(email: str):
    """
    Returns:
      - list of breach objects if breaches found
      - [] if none
      - None if service error
    """
    if not email:
        return []
    try:
        url = f"https://api.xposedornot.com/v1/check-email/{quote(email)}"
        resp = requests.get(url, timeout=10, headers={"User-Agent": "AuthNova"})
        if resp.status_code == 200:
            data = resp.json()
            # XposedOrNot might return {'breaches': [...] } or list directly
            if isinstance(data, dict):
                return data.get('breaches') or data.get('data') or []
            if isinstance(data, list):
                return data
            return []
        if resp.status_code == 404:
            return []
        # unexpected
        return None
    except requests.RequestException as e:
        print("Email breach request error:", e)
        return None
    except Exception as e:
        print("Email breach unexpected error:", e)
        return None