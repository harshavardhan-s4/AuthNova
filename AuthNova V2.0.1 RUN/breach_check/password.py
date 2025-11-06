import hashlib
import requests

def check_password_breach(password: str):
    """
    Returns:
      - int > 0 : number of times seen in breaches
      - 0        : not found
      - None     : error/unavailable
    """
    if not password:
        return 0
    try:
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        resp = requests.get(url, timeout=10, headers={"User-Agent": "AuthNova"})
        if resp.status_code != 200:
            print("Pwned API status:", resp.status_code)
            return None
        for line in resp.text.splitlines():
            if ':' not in line:
                continue
            part, count = line.split(':', 1)
            if part.strip().upper() == suffix:
                try:
                    return int(count.strip())
                except Exception:
                    return None
        return 0
    except requests.RequestException as e:
        print("Password check request error:", e)
        return None
    except Exception as e:
        print("Password check unexpected error:", e)
        return None