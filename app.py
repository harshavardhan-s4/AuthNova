from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, session, jsonify, flash, url_for
from auth import register_user, validate_login
from breach_check.email import check_email_breach
from breach_check.password import check_password_breach
# notifications integration removed (reverted)
from vault import get_vault, add_entry, delete_entry
from vault_monitor import check_vault_entries
from vault_challenge import VaultChallenge
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Ensure data directories exist
os.makedirs('data/vaults', exist_ok=True)
if not os.path.exists('data/users.json'):
    with open('data/users.json', 'w') as f:
        f.write('{}')

vault_challenge = VaultChallenge()

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
        print(f"Error rendering alerts: {e}")
        # show empty list so template can render the "safe" box
        flash("Could not load alerts right now.", "error")
        return render_template('alerts.html', breaches=[])

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
def login():
    if 'user' in session:
        return redirect(url_for_safe('dashboard'))
        
    if request.method == 'POST':
        try:
            # Get form data (we'll handle JSON separately if needed)
            username = request.form.get('username')
            password = request.form.get('password')
            
            if not username or not password:
                flash("Please provide both username and password", "error")
                return render_template('login.html')  # Return to form with error
            
            if validate_login(username, password):
                session['user'] = username
                session['last_login'] = datetime.now().isoformat()
                flash("Login successful!", "success")
                return redirect(url_for('dashboard'))  # Redirect on success
            else:
                flash("Invalid username or password", "error")
                return render_template('login.html')  # Return to form with error
                
        except Exception as e:
            print(f"Login error: {e}")
            flash("An error occurred during login", "error")
            return render_template('login.html')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user' in session:
        return redirect(url_for_safe('dashboard'))
        
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            
            # Validate input
            if not username or not password:
                flash("Please provide both username and password", "error")
                return render_template('register.html')
            
            if len(password) < 8:
                flash("Password must be at least 8 characters long", "error")
                return render_template('register.html')
            
            if len(username) < 3:
                flash("Username must be at least 3 characters long", "error")
                return render_template('register.html')
            
            # Try to register
            print(f"Attempting to register user: {username}")  # Debug print
            success = register_user(username, password)
            
            if success:
                flash("Registration successful! Please login.", "success")
                return redirect(url_for('login'))
            else:
                flash("Username already exists or registration failed", "error")
                return render_template('register.html')
                
        except Exception as e:
            print(f"Registration error: {e}")  # Debug print
            flash("An error occurred during registration", "error")
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
        print(f"Error getting vault entries: {e}")
        flash("Error loading vault entries", "error")
        return render_template('vault.html', entries=[])

@app.route('/add_entry', methods=['POST'])
@login_required
def add_entry_route():
    # Handle both JSON and form data
    data = request.get_json() or request.form.to_dict()
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
        print(f"Error adding entry: {e}")
        if request.is_json:
            return jsonify(success=False, error="Failed to add entry"), 500
        flash("Failed to add entry", "error")
        return redirect(url_for('vault'))

@app.route('/delete_entry', methods=['POST'])
@login_required
def delete_entry_route():
    data = request.get_json() or request.form.to_dict()
    label = data.get('label')
    if not label:
        return jsonify(success=False, error="Missing label"), 400
    try:
        delete_entry(session['user'], label)
        # removed flash() here to avoid duplicate notification in the navigation bar
        return jsonify(success=True)
    except Exception as e:
        print(f"Error deleting entry: {e}")
        return jsonify(success=False, error="Failed to delete"), 500

@app.route('/check_email', methods=['GET', 'POST'])
@login_required
def check_email():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            return render_template('check_email.html', error="Please provide an email address")

        try:
            result = check_email_breach(email)
            print(f"Email check result: {result}")  # Debug print

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
            print(f"Error checking email:", str(e))
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
            print(f"Password check count: {count}")  # Debug print

            # Render template with result rather than using flashes
            return render_template('check_password.html', count=count, has_result=True)
        except Exception as e:
            print(f"Error checking password: {e}")
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
        print("Error calculating trust score:", exc)
        return jsonify({'score': 60}), 500

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
    return 'pong'

@app.route('/vault-challenge', methods=['GET', 'POST'])
def vault_challenge_route():
    if request.method == 'POST':
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
    print("Starting AuthNova server...")
    try:
        app.debug = True
        app.run(host="127.0.0.1", port=5000)
    except Exception as e:
        print(f"Error starting server: {e}")