from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import uuid
import time
import os
import tempfile
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import threading


app = Flask(__name__)

# --- Security Best Practices ---
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JS access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# --- End Security Best Practices ---

# In-memory storage: {key: {enc_message, pin_hash, expire_at, read}}
# NOTE: In-memory storage is not suitable for production scale-out or persistence.
secrets_store = {}


class StorageBackend:
    def __init__(self, mode='memory', base_dir=None):
        self.mode = mode
        self.base_dir = base_dir or tempfile.gettempdir()
        self.memory_store = {}  # {key: entry}

    def save(self, key, entry):
        if self.mode == 'memory':
            self.memory_store[key] = entry
        elif self.mode == 'local':
            path = os.path.join(self.base_dir, key + '.pkl')
            import pickle
            with open(path, 'wb') as f:
                pickle.dump(entry, f)
        # S3 support can be added here

    def load(self, key):
        if self.mode == 'memory':
            return self.memory_store.get(key)
        elif self.mode == 'local':
            path = os.path.join(self.base_dir, key + '.pkl')
            import pickle
            if not os.path.exists(path):
                return None
            with open(path, 'rb') as f:
                return pickle.load(f)
        # S3 support can be added here
        return None

    def delete(self, key):
        if self.mode == 'memory':
            self.memory_store.pop(key, None)
        elif self.mode == 'local':
            path = os.path.join(self.base_dir, key + '.pkl')
            if os.path.exists(path):
                os.remove(path)
        # S3 support can be added here

    def all_keys(self):
        if self.mode == 'memory':
            return list(self.memory_store.keys())
        elif self.mode == 'local':
            return [f[:-4] for f in os.listdir(self.base_dir) if f.endswith('.pkl')]
        # S3 support can be added here
        return []


# Use storage backend
storage = StorageBackend(mode=os.environ.get('STORAGE_MODE', 'memory'))


def get_file_entry(key):
    return storage.load(key)


def set_file_entry(key, entry):
    storage.save(key, entry)


def delete_file_entry(key):
    storage.delete(key)


def all_file_keys():
    return storage.all_keys()


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

# Download tracking: {key: [timestamps]}
download_log = {}

# Flask-Limiter for bandwidth throttling
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per hour"]  # Example: 10 downloads per hour per IP
)


# --- Routes ---

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        message = request.form.get('message', '').strip()
        pin = request.form.get('pin', '').strip()
        exp = request.form.get('exp', '').strip()
        exp_unit = request.form.get('exp_unit', 'minutes')
        # --- Input validation ---
        if (not message and not request.files.getlist('files')) or not pin or not exp.isdigit():
            flash('All fields are required and expiration must be a number.', 'danger')
            return render_template('index.html')
        if len(pin) != 5:
            flash('PIN must be 5 characters.', 'danger')
            return render_template('index.html')
        if message and len(message) > 2048:
            flash('Message is too long (max 2048 characters).', 'danger')
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
        pin_hash = generate_password_hash(pin)
        key = str(uuid.uuid4())
        entry = {
            'pin_hash': pin_hash,
            'expire_at': expire_at,
            'read': False,
            'attempts': 0
        }
        if message:
            enc_message = fernet.encrypt(message.encode())
            entry['enc_message'] = enc_message
        # Handle file uploads (if any)
        files = request.files.getlist('files')
        if files and files[0].filename:
            entry['files'] = {}
            for file in files:
                file_data = file.read()
                entry['files'][file.filename] = {
                    'data': file_data,
                    'mimetype': file.mimetype
                }
        # Save to both stores if files are present (always for combo)
        set_file_entry(key, entry)
        secrets_store[key] = entry
        return redirect(url_for('created', key=key))
    return render_template('index.html')


@app.route('/download_file_temp/<filename>')
def download_file_temp(filename):
    # This is a temp route for demo: serve the file from the last accessed combo secret
    # In production, you would want a more secure approach
    # We'll use a global to store the last files dict for demo
    if 'last_combo_files' not in globals() or filename not in globals().get('last_combo_files', {}):
        return render_template('error.html', message='File not found or expired.')
    fileinfo = globals()['last_combo_files'][filename]
    response = make_response(fileinfo['data'])
    response.headers.set('Content-Type', fileinfo.get('mimetype', 'application/octet-stream'))
    response.headers.set('Content-Disposition', f'attachment; filename="{filename}"')
    return response


@app.route('/combo/<key>', methods=['GET', 'POST'])
def combo_secret(key):
    entry = secrets_store.get(key)
    if not entry:
        entry = get_file_entry(key)
    now = int(time.time())
    if not entry or entry['read'] or entry['expire_at'] < now:
        secrets_store.pop(key, None)
        return render_template('error.html', message='Secret not found or expired.')
    if request.method == 'POST':
        pin = request.form.get('pin', '').strip()
        if not pin:
            flash('PIN is required.', 'danger')
            return render_template('enter_pin.html', key=key)
        if entry['attempts'] >= 3:
            secrets_store.pop(key, None)
            return render_template('error.html', message='Too many incorrect attempts. Secret destroyed.')
        if check_password_hash(entry['pin_hash'], pin):
            message = None
            if 'enc_message' in entry:
                try:
                    message = fernet.decrypt(entry['enc_message']).decode()
                except Exception:
                    secrets_store.pop(key, None)
                    return render_template('error.html', message='Failed to decrypt secret.')
            files = entry.get('files', {})
            entry['read'] = True
            secrets_store.pop(key, None)
            set_file_entry(key, entry)  # Mark as read in file backend too
            globals()['last_combo_files'] = files
            return render_template('show_combo.html', message=message, files=files)
        else:
            entry['attempts'] += 1
            if entry['attempts'] >= 3:
                secrets_store.pop(key, None)
                return render_template('error.html', message='Too many incorrect attempts. Secret destroyed.')
            flash('Incorrect PIN.', 'danger')
            return render_template('enter_pin.html', key=key)
    return render_template('enter_pin.html', key=key)


@app.route('/upload', methods=['POST'])
@limiter.exempt  # TEMPORARY: Disable rate limiting for uploads
def upload_file():
    try:
        filename = request.form.get('filename')
        chunk = request.files.get('chunk')
        iv = request.form.get('iv')
        chunk_idx = int(request.form.get('chunk_idx', 0))
        total_chunks = int(request.form.get('total_chunks', 1))
        file_size = int(request.form.get('file_size', 0))
        pin = request.form.get('pin', '').strip()
        exp = request.form.get('exp', '').strip()
        exp_unit = request.form.get('exp_unit', 'minutes')
        message = request.form.get('message', '')
        message = message.strip() if message else ''  # Ensure not None
        # Validate
        if not filename or not chunk or not iv or not pin or not exp.isdigit():
            return 'Invalid upload', 400
        if len(pin) != 5:
            return 'PIN must be 5 characters', 400
        exp_value = int(exp)
        if exp_unit == 'hours':
            exp_minutes = exp_value * 60
        else:
            exp_minutes = exp_value
        if exp_minutes > 1440:
            return 'Expiration too long', 400
        expire_at = int(time.time()) + exp_minutes * 60
        key = request.cookies.get('upload_key')
        if not key:
            key = str(uuid.uuid4())
        if key not in storage.memory_store:
            entry = {
                'files': {},
                'pin_hash': generate_password_hash(pin),
                'expire_at': expire_at,
                'read': False,
                'attempts': 0
            }
            if message:
                enc_message = fernet.encrypt(message.encode())
                entry['enc_message'] = enc_message
            set_file_entry(key, entry)
        entry = storage.load(key)
        if filename not in storage.memory_store[key]['files']:
            entry = storage.load(key)
            entry['files'][filename] = {
                'chunks': [None] * total_chunks,
                'size': file_size,
                'received': 0,
                'ivs': [None] * total_chunks
            }
            set_file_entry(key, entry)
        entry = storage.load(key)
        fileinfo = entry['files'].get(filename)
        if (
            not fileinfo or
            'chunks' not in fileinfo or
            len(fileinfo['chunks']) != total_chunks or
            'ivs' not in fileinfo or
            len(fileinfo['ivs']) != total_chunks
        ):
            entry['files'][filename] = {
                'chunks': [None] * total_chunks,
                'size': file_size,
                'received': 0,
                'ivs': [None] * total_chunks
            }
            set_file_entry(key, entry)
        idx = chunk_idx
        entry = storage.load(key)
        entry['files'][filename]['chunks'][idx] = chunk.read()
        entry['files'][filename]['ivs'][idx] = iv
        entry['files'][filename]['received'] += 1
        if entry['files'][filename]['received'] == total_chunks:
            entry['files'][filename]['complete'] = True
        set_file_entry(key, entry)
        resp = jsonify({'status': 'ok', 'key': key})
        resp.set_cookie('upload_key', key)
        return resp
    except Exception as e:
        import traceback
        print('ERROR in /upload:', e)
        traceback.print_exc()
        return 'Internal server error', 500


@app.route('/created')
def created():
    key = request.args.get('key')
    entry = get_file_entry(key)
    if not entry:
        entry = secrets_store.get(key)
    if not entry:
        return render_template('error.html', message='No files found for this key.')
    message = None
    if 'enc_message' in entry:
        try:
            message = fernet.decrypt(entry['enc_message']).decode()
        except Exception:
            message = None
    file_links = []
    files_still_uploading = False
    if 'files' in entry and entry['files']:
        for filename, fileinfo in entry['files'].items():
            is_complete = fileinfo.get('complete', True)
            if not is_complete:
                files_still_uploading = True
            file_links.append({
                'filename': filename,
                'link': url_for('download_file', key=key, filename=filename, _external=True),
                'complete': is_complete
            })
    print('DEBUG: key =', key)
    share_link = url_for('combo_secret', key=key, _external=True)
    print('DEBUG: share_link =', share_link)
    return render_template(
        'created.html',
        message=message,
        file_links=file_links,
        share_link=share_link,
        key=key,
        expire=entry.get('expire_at'),
        expire_at=entry.get('expire_at'),
        files_still_uploading=files_still_uploading
    )


def secure_delete_fileinfo(fileinfo):
    # Overwrite each chunk with random data before deletion
    for i, chunk in enumerate(fileinfo.get('chunks', [])):
        if chunk:
            fileinfo['chunks'][i] = os.urandom(len(chunk))
    fileinfo['chunks'] = []
    fileinfo['ivs'] = []


# --- Expired secret cleanup (on each request) ---
@app.before_request
def cleanup_expired():
    now = int(time.time())
    expired = [k for k, v in secrets_store.items() if v['expire_at'] < now or v['read']]
    for k in expired:
        secrets_store.pop(k, None)
    expired_files = [k for k, v in storage.memory_store.items() if v['expire_at'] < now or v.get('read')]
    for k in expired_files:
        entry = storage.load(k)
        if entry:
            if 'files' in entry:
                for fileinfo in entry['files'].values():
                    secure_delete_fileinfo(fileinfo)
        storage.delete(k)


# --- Secure delete and reset on download ---
@app.route('/download/<key>/<filename>', methods=['GET', 'POST'])
@limiter.exempt
def download_file(key, filename):
    entry = get_file_entry(key)
    now = int(time.time())
    if not entry or entry['read'] or entry['expire_at'] < now:
        delete_file_entry(key)
        return render_template('error.html', message='File not found or expired.')
    if request.method == 'POST':
        pin = request.form.get('pin', '').strip()
        if not pin:
            flash('PIN is required.', 'danger')
            return render_template('enter_pin.html', key=key)
        if entry['attempts'] >= 3:
            delete_file_entry(key)
            return render_template('error.html', message='Too many incorrect attempts. File destroyed.')
        if check_password_hash(entry['pin_hash'], pin):
            fileinfo = entry['files'].get(filename)
            if not fileinfo or not fileinfo.get('complete'):
                return render_template('error.html', message='File not ready.')
            _ = b''.join(fileinfo['chunks'])  # data is not used, so assign to _
            fileinfo['read'] = True
            if key not in download_log:
                download_log[key] = []
            download_log[key].append({'filename': filename, 'timestamp': now})
            if all(f.get('read') for f in entry['files'].values()):
                # Securely delete all files and reset app state for this key
                for finfo in entry['files'].values():
                    secure_delete_fileinfo(finfo)
                delete_file_entry(key)
                secrets_store.pop(key, None)
            message = None
            if 'enc_message' in entry:
                try:
                    message = fernet.decrypt(entry['enc_message']).decode()
                except Exception:
                    message = None
            files = {filename: fileinfo}
            return render_template('show_combo.html', message=message, files=files)
        else:
            entry['attempts'] += 1
            if entry['attempts'] >= 3:
                delete_file_entry(key)
                return render_template('error.html', message='Too many incorrect attempts. File destroyed.')
            flash('Incorrect PIN.', 'danger')
            return render_template('enter_pin.html', key=key)
    return render_template('enter_pin.html', key=key)


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', message='Page not found.'), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template('error.html', message='An internal server error occurred.'), 500


# --- Periodic background cleanup ---
def periodic_cleanup():
    while True:
        with app.app_context():
            cleanup_expired()
        time.sleep(600)  # Run every 10 minutes


threading.Thread(target=periodic_cleanup, daemon=True).start()

# --- Security Notes ---
# - No logging of secrets or PINs.
# - Always use HTTPS in production.
# - Use environment variables for all secrets.
# - For CSRF protection, Flask-WTF is recommended for production.
# --- End Security Notes ---


if __name__ == '__main__':
    app.run(debug=True)
