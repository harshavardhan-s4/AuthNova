from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, session, jsonify, flash, url_for
import secrets
import logging
from flask_wtf import CSRFProtect
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from auth import register_user, validate_login, sanitize_username
from breach_check.email import check_email_breach
from breach_check.password import check_password_breach
# notifications integration removed (reverted)
from vault import get_vault, add_entry, delete_entry
from vault_monitor import check_vault_entries
from vault_challenge import VaultChallenge
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)

# Use environment-provided secrets; generate a fallback but warn
app = Flask(__name__, template_folder="templates", static_folder="static")
load_dotenv()
# Use environment-provided secrets; generate a fallback but warn
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret')
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # Set True on production HTTPS
    SESSION_COOKIE_SAMESITE='Lax'
)
if os.environ.get('FLASK_ENV') == 'production':
    app.config['SESSION_COOKIE_SECURE'] = True
app.permanent_session_lifetime = timedelta(days=1)

# CSRF protection
csrf = CSRFProtect(app)

# Rate limiter (Flask-Limiter v3+)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per hour"]
)
# Initialize limiter with the Flask app
limiter.init_app(app)

# Configure logging
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# Ensure data directories exist
os.makedirs(os.path.join(DATA_DIR, 'vaults'), exist_ok=True)
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        f.write('{}')

vault_challenge = VaultChallenge()

# Check for vault master key usage and warn if missing
if not os.environ.get('VAULT_MASTER_KEY'):
    app.logger.warning('VAULT_MASTER_KEY not set: vault files will be stored in plaintext unless you configure it.')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            # preserve next if needed
            return redirect(url_for_safe('login'))
        return f(*args, **kwargs)
    return decorated_function

# Remove these routes:
# @app.route('/api/check-vault')
# @app.route('/api/notifications')

# Keep only the /alerts route for the dedicated alerts page
@app.route('/alerts')
@login_required
def alerts():
    """Dedicated page for security alerts"""
    try:
        # get breached entries for current user and pass to template
        breaches = check_vault_entries(session['user'])
        return render_template('alerts.html', breaches=breaches)
    except Exception as e:
        app.logger.error("Error rendering alerts: %s", e)
        # show empty list so template can render the "safe" box
        flash("Could not load alerts right now.", "error")
        return render_template('alerts.html', breaches=[])


@app.route('/api/check-vault')
@login_required
@limiter.limit('30 per hour')
def api_check_vault():
    try:
        breaches = check_vault_entries(session.get('user'))
        return jsonify({'count': len(breaches), 'breaches': breaches})
    except Exception as e:
        app.logger.error('Error in api_check_vault: %s', e)
        return jsonify({'count': 0, 'breaches': []}), 500

# Add this helper function
def url_for_safe(*args, **kwargs):
    try:
        return url_for(*args, **kwargs)
    except Exception:
        return '/'

# Update your routes to use explicit endpoints
@app.route('/')
def home():
    if 'user' not in session:
        return redirect(url_for_safe('login'))
    return redirect(url_for_safe('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get the user's vault challenge progress from session or set defaults
    if 'auth_points' not in session:
        session['auth_points'] = 0
    if 'vault_level' not in session:
        session['vault_level'] = 'Level 1'
        
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def login():
    if 'user' in session:
        return redirect(url_for_safe('dashboard'))
        
    if request.method == 'POST':
        try:
            # Get form data (we'll handle JSON separately if needed)
            if request.is_json:
                data = request.get_json()
                username = data.get('username')
                password = data.get('password')
            else:
                username = request.form.get('username')
                password = request.form.get('password')
            username = sanitize_username(username or '')
            
            if not username or not password:
                flash("Please provide both username and password", "error")
                return render_template('login.html')  # Return to form with error
            
            if validate_login(username, password):
                session['user'] = username
                session['last_login'] = datetime.now().isoformat()
                flash("Login successful!", "success")
                if request.is_json:
                    return jsonify(success=True)
                return redirect(url_for('dashboard'))  # Redirect on success
            else:
                flash("Invalid username or password", "error")
                if request.is_json:
                    return jsonify(success=False, error='Invalid username or password'), 401
                return render_template('login.html')  # Return to form with error
                
        except Exception as e:
            app.logger.exception("Login error: %s", e)
            flash("An error occurred during login", "error")
            if request.is_json:
                return jsonify(success=False, error='Login error'), 500
            return render_template('login.html')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit('5 per minute')
def register():
    if 'user' in session:
        return redirect(url_for_safe('dashboard'))
        
    if request.method == 'POST':
        try:
            if request.is_json:
                data = request.get_json() or {}
                username = sanitize_username((data.get('username') or '').strip())
                password = (data.get('password') or '').strip()
            else:
                username = sanitize_username(request.form.get('username', '').strip())
                password = request.form.get('password', '').strip()
            
            # Validate input
            if not username or not password:
                flash("Please provide both username and password", "error")
                return render_template('register.html')
            
            if len(password) < 8:
                flash("Password must be at least 8 characters long", "error")
                return render_template('register.html')

            # Enforce password strength at registration using vault_challenge
            try:
                pw_result = vault_challenge.evaluate_password(password)
            except Exception as e:
                app.logger.exception("Password strength evaluation failed: %s", e)
                pw_result = None

            if pw_result:
                # Reject breached passwords entirely
                if pw_result.get('breach_count', 0) and pw_result['breach_count'] > 0:
                    err = "This password appears in known breaches. Choose a different one."
                    flash(err, "error")
                    if request.is_json:
                        return jsonify(success=False, error=err), 400
                    return render_template('register.html')

                # Require a minimum auth_points threshold for a new password
                min_points = 50
                if pw_result.get('auth_points', 0) < min_points:
                    err = f"Password too weak (auth points {pw_result.get('auth_points')}). {pw_result.get('feedback', '')}"
                    flash(err, "error")
                    if request.is_json:
                        return jsonify(success=False, error=err), 400
                    return render_template('register.html')
            
            if len(username) < 3:
                flash("Username must be at least 3 characters long", "error")
                return render_template('register.html')
            
            # Try to register
            app.logger.info(f"Attempting to register user: {username}")
            success = register_user(username, password)
            
            if success:
                flash("Registration successful! Please login.", "success")
                if request.is_json:
                    return jsonify(success=True)
                return redirect(url_for('login'))
            else:
                flash("Username already exists or registration failed", "error")
                if request.is_json:
                    return jsonify(success=False, error='Username already exists or registration failed'), 400
                return render_template('register.html')
                
        except Exception as e:
            app.logger.exception("Registration error: %s", e)
            flash("An error occurred during registration", "error")
            if request.is_json:
                return jsonify(success=False, error='Registration error'), 500
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    # Clear user session
    session.pop('user', None)
    # Add flash message for popup notification
    flash("Successfully logged out!", "success")
    return redirect(url_for('login'))

@app.route('/vault')
@login_required
def vault():
    try:
        entries = get_vault(session['user']) or []  # Ensure entries is at least an empty list
        return render_template('vault.html', entries=entries)
    except Exception as e:
        app.logger.exception("Error getting vault entries: %s", e)
        flash("Error loading vault entries", "error")
        return render_template('vault.html', entries=[])

@app.route('/add_entry', methods=['POST'])
@login_required
@limiter.limit('60 per hour')
def add_entry_route():
    # Handle both JSON and form data
    data = request.get_json(silent=True) or request.form.to_dict()
    label = data.get('label')
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    # Validate required fields
    if not all([label, username, password]):
        if request.is_json:
            return jsonify(success=False, error="Missing required fields"), 400
        flash("Missing required fields", "error")
        return redirect(url_for('vault'))

    try:
        # Add the entry
        add_entry(session['user'], label, username, password, email)
        
        # Handle response based on request type
        if request.is_json:
            return jsonify({
                'success': True,
                'message': f"Added entry: {label}"
            })
        
        # For regular form submissions
        flash(f"Added entry: {label}", "success")
        return redirect(url_for('vault'))

    except Exception as e:
        app.logger.exception("Error adding entry: %s", e)
        if request.is_json:
            return jsonify(success=False, error="Failed to add entry"), 500
        flash("Failed to add entry", "error")
        return redirect(url_for('vault'))

@app.route('/delete_entry', methods=['POST'])
@login_required
@limiter.limit('60 per hour')
def delete_entry_route():
    data = request.get_json(silent=True) or request.form.to_dict()
    label = data.get('label')
    if not label:
        return jsonify(success=False, error="Missing label"), 400
    try:
        delete_entry(session['user'], label)
        # removed flash() here to avoid duplicate notification in the navigation bar
        return jsonify(success=True)
    except Exception as e:
        app.logger.exception("Error deleting entry: %s", e)
        return jsonify(success=False, error="Failed to delete"), 500

@app.route('/check_email', methods=['GET', 'POST'])
@login_required
def check_email():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip()
        if not email:
            return render_template('check_email.html', error="Please provide an email address")

        try:
            result = check_email_breach(email)
            app.logger.debug("Email check result: %s", result)

            # Normalize results into a list of human-friendly "places"
            breaches = []
            if result:
                if isinstance(result, list):
                    for r in result:
                        if isinstance(r, dict):
                            name = r.get('Name') or r.get('name') or r.get('Title') or r.get('title') or str(r)
                        else:
                            name = str(r)
                        breaches.append(name)
                elif isinstance(result, dict):
                    # common APIs may return dict with "breaches" or "data"
                    maybe = result.get('breaches') or result.get('data') or result.get('items')
                    if isinstance(maybe, list):
                        for r in maybe:
                            if isinstance(r, dict):
                                name = r.get('Name') or r.get('name') or r.get('title') or str(r)
                            else:
                                name = str(r)
                            breaches.append(name)
                    else:
                        breaches = [str(result)]
                elif isinstance(result, int):
                    breaches = [f"Found in {result} breaches"]
                else:
                    breaches = [str(result)]

            return render_template(
                'check_email.html',
                email=email,
                breaches=breaches,
                has_result=True
            )

        except Exception as e:
            app.logger.exception("Error checking email: %s", e)
            return render_template('check_email.html',
                                   email=email,
                                   error="Error checking email",
                                   has_result=True)
    return render_template('check_email.html')

@app.route('/check_password', methods=['GET', 'POST'])
@login_required
def check_password():
    if request.method == 'POST':
        password = request.form.get('password')
        if not password:
            return render_template('check_password.html', error="Please enter a password")

        try:
            count = check_password_breach(password)
            app.logger.debug("Password check count: %s", count)

            # Render template with result rather than using flashes
            return render_template('check_password.html', count=count, has_result=True)
        except Exception as e:
            app.logger.exception("Error checking password: %s", e)
            return render_template('check_password.html', error="Error checking password", has_result=True)

    return render_template('check_password.html')

@app.route('/api/trust-score')
@login_required
def get_trust_score():
    """
    Calculate a trust score (0-100) based on how safe the passwords and emails
    stored in the user's vault appear.
    """
    try:
        username = session.get('user')
        entries = get_vault(username) or []

        # If no entries, return 0 per requirement
        if not entries:
            return jsonify({'score': 0})

        total_entries = len(entries)
        per_entry_risks = []
        for e in entries:
            try:
                pwd = e.get('password') or ""
                email = e.get('email') or None

                pwd_breach_count = 0
                try:
                    res = check_password_breach(pwd) if pwd else 0
                    if isinstance(res, int):
                        pwd_breach_count = res
                    elif isinstance(res, dict) and 'count' in res:
                        pwd_breach_count = int(res.get('count') or 0)
                except Exception:
                    pwd_breach_count = 0

                pwd_breached = bool(pwd_breach_count and pwd_breach_count > 0)

                email_breach_count = 0
                if email:
                    try:
                        eres = check_email_breach(email)
                        if isinstance(eres, int):
                            email_breach_count = eres
                        elif isinstance(eres, list):
                            email_breach_count = len(eres)
                        elif isinstance(eres, dict) and 'count' in eres:
                            email_breach_count = int(eres.get('count') or 0)
                    except Exception:
                        email_breach_count = 0

                email_breached = bool(email_breach_count and email_breach_count > 0)

                weak_pwd = len(pwd) < 12

                risk = 0.0
                if pwd_breached:
                    risk += 0.6
                if weak_pwd:
                    risk += 0.2
                if email_breached:
                    risk += 0.2

                if risk > 1.0:
                    risk = 1.0
                per_entry_risks.append(risk)
            except Exception:
                per_entry_risks.append(0.35)

        avg_risk = sum(per_entry_risks) / max(1, total_entries)
        score = round((1.0 - avg_risk) * 100)
        score = max(0, min(100, score))

        return jsonify({'score': score})
    except Exception as exc:
        app.logger.exception("Error calculating trust score: %s", exc)
        return jsonify({'score': 60}), 500

if os.environ.get('FLASK_ENV') != 'production':
    @app.route('/debug')
    def debug():
        return jsonify({
            'status': 'running',
            'time': datetime.now().isoformat(),
            'user': session.get('user'),
            'session': dict(session)
        })

@app.route('/ping')
def ping():
    return 'OK', 200


@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    response.headers['Permissions-Policy'] = 'geolocation=()'
    # Minimal CSP; adapt for assets if needed
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    return response

@app.route('/vault-challenge', methods=['GET', 'POST'])
def vault_challenge_route():
    if request.method == 'POST':
        if request.is_json:
            password = request.get_json().get('password')
        else:
            password = request.form.get('password')
        if not password:
            return jsonify({'error': 'No password provided'}), 400
            
        result = vault_challenge.evaluate_password(password)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(result)
        return render_template('vault_challenge.html', result=result)
        
    return render_template('vault_challenge.html')

# At the bottom of the file
if __name__ == "__main__":
    app.logger.info("Starting AuthNova server (development mode)...")
    try:
        app.run(host="127.0.0.1", port=int(os.environ.get('PORT', 5000)))
    except Exception as e:
        app.logger.exception("Error starting server: %s", e)