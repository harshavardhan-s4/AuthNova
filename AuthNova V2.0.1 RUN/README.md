AuthNova - Local Vault and Breach Checker

Overview
- AuthNova is a Flask-based app that provides a simple local password vault, breach checking via 3rd-party APIs, and a password strength challenge.

New Security Improvements
- Password hashing: Uses Argon2 (argon2-cffi) for user passwords with automatic migration from legacy SHA256.
- Vault encryption: Vault JSON files are encrypted using Fernet (cryptography) with a master key stored in VAULT_MASTER_KEY environment variable.
- CSRF protection: All forms and AJAX requests include CSRF tokens (Flask-WTF).
- Rate-limiting: Login and registration endpoints are rate-limited with Flask-Limiter.
- Input sanitization: Usernames are sanitized before being used as filenames to avoid path traversal.
- Cookie settings: Session cookie has HTTPOnly and SameSite flags; set SESSION_COOKIE_SECURE True in production.
- Security headers: Added common security headers (CSP, X-Frame-Options, etc.).

Setup
1. Create a virtualenv and install dependencies:

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

2. Generate a vault key (recommended) and set environment variables, or create `.env` from `.env.example`:

```bash
python scripts/generate_vault_key.py
# Copy the printed key into .env as VAULT_MASTER_KEY
# Set FLASK_SECRET_KEY to a secure string as well
```

3. Run the app for development:

```bash
python app.py
```

Notes
- For production, use HTTPS and set `SESSION_COOKIE_SECURE=True` in environment or config.
- If `VAULT_MASTER_KEY` is not set, the vault will remain plaintext on disk, with a strong warning logged.
- Avoid using the application with real sensitive credentials until vault encryption is configured properly and the instance is deployed with production settings.
