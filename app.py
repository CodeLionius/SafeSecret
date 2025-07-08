from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import uuid
import time
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change in production

# In-memory storage: {key: {enc_message, pin_hash, expire_at, read}}
secrets_store = {}

# Fernet key for encryption (should be kept secret in production)
fernet_key = os.environ.get('FERNET_KEY')
if not fernet_key:
    # For development only: generate a key if not set
    fernet_key = Fernet.generate_key()
    if os.environ.get('FLASK_ENV') == 'production':
        raise RuntimeError('FERNET_KEY environment variable must be set in production!')
    # Optionally, print a warning in development
    print('WARNING: Using a generated Fernet key. Set FERNET_KEY in production!')
if isinstance(fernet_key, str):
    fernet_key = fernet_key.encode()
fernet = Fernet(fernet_key)

# --- Routes ---

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        message = request.form.get('message', '').strip()
        pin = request.form.get('pin', '').strip()
        exp = request.form.get('exp', '').strip()
        exp_unit = request.form.get('exp_unit', 'minutes')
        if not message or not pin or not exp.isdigit():
            flash('All fields are required and expiration must be a number.', 'danger')
            return render_template('index.html')
        if len(pin) != 5:
            flash('PIN must be 5 characters.', 'danger')
            return render_template('index.html')
        exp_value = int(exp)
        if exp_unit == 'hours':
            exp_minutes = exp_value * 60
        else:
            exp_minutes = exp_value
        if exp_minutes > 1440:
            flash('Expiration cannot exceed 24 hours (1440 minutes).', 'danger')
            return render_template('index.html')
        expire_at = int(time.time()) + exp_minutes * 60
        enc_message = fernet.encrypt(message.encode())
        pin_hash = generate_password_hash(pin)
        key = str(uuid.uuid4())
        secrets_store[key] = {
            'enc_message': enc_message,
            'pin_hash': pin_hash,
            'expire_at': expire_at,
            'read': False,
            'attempts': 0
        }
        link = url_for('get_secret', key=key, _external=True)
        return render_template('created.html', link=link, expire=exp_minutes, expire_at=expire_at)
    return render_template('index.html')

@app.route('/secret/<key>', methods=['GET', 'POST'])
def get_secret(key):
    secret = secrets_store.get(key)
    now = int(time.time())
    if not secret or secret['read'] or secret['expire_at'] < now:
        secrets_store.pop(key, None)
        return render_template('error.html', message='Secret not found or expired.')
    if request.method == 'POST':
        pin = request.form.get('pin', '').strip()
        if not pin:
            flash('PIN is required.', 'danger')
            return render_template('enter_pin.html', key=key)
        if secret['attempts'] >= 3:
            secrets_store.pop(key, None)
            return render_template('error.html', message='Too many incorrect attempts. Secret destroyed.')
        if check_password_hash(secret['pin_hash'], pin):
            try:
                message = fernet.decrypt(secret['enc_message']).decode()
            except Exception:
                secrets_store.pop(key, None)
                return render_template('error.html', message='Failed to decrypt secret.')
            secret['read'] = True
            secrets_store.pop(key, None)
            return render_template('show_secret.html', message=message)
        else:
            secret['attempts'] += 1
            if secret['attempts'] >= 3:
                secrets_store.pop(key, None)
                return render_template('error.html', message='Too many incorrect attempts. Secret destroyed.')
            flash('Incorrect PIN.', 'danger')
            return render_template('enter_pin.html', key=key)
    return render_template('enter_pin.html', key=key)

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', message='Page not found.'), 404

# --- Expired secret cleanup (on each request) ---
@app.before_request
def cleanup_expired():
    now = int(time.time())
    expired = [k for k, v in secrets_store.items() if v['expire_at'] < now or v['read']]
    for k in expired:
        secrets_store.pop(k, None)

if __name__ == '__main__':
    app.run(debug=True) 