import os
import pytest
from app import app, secrets_store, fernet, limiter
import time
import io

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['RATELIMIT_ENABLED'] = False
    limiter.enabled = False  # Explicitly disable Flask-Limiter
    with app.test_client() as client:
        yield client

# Helper to clear secrets_store between tests
def clear_store():
    secrets_store.clear()

# Test secret creation and retrieval
def test_secret_lifecycle(client):
    clear_store()
    # Create secret
    resp = client.post('/', data={
        'message': 'my secret',
        'pin': '12345',
        'exp': '1',
        'exp_unit': 'minutes'
    }, follow_redirects=True)
    # Should redirect to /created page
    assert b'Secret Link Created!' in resp.data or b'File Upload Complete' in resp.data
    # Extract key from the store
    for k in secrets_store:
        key = k
        break
    # Access secret page (GET)
    resp = client.get(f'/combo/{key}')
    assert b'Enter PIN' in resp.data or b'PIN is required' in resp.data
    # Submit correct PIN
    resp = client.post(f'/combo/{key}', data={'pin': '12345'})
    assert b'my secret' in resp.data
    # Secret should be destroyed after read
    assert key not in secrets_store

# Test wrong PIN and attempts
def test_wrong_pin_attempts(client):
    clear_store()
    client.post('/', data={
        'message': 'test',
        'pin': 'abcde',
        'exp': '1',
        'exp_unit': 'minutes'
    })
    key = next(iter(secrets_store))
    # 2 wrong attempts
    for _ in range(2):
        resp = client.post(f'/combo/{key}', data={'pin': 'wrong1'})
        assert b'Incorrect PIN' in resp.data
    # 3rd wrong attempt destroys secret
    resp = client.post(f'/combo/{key}', data={'pin': 'wrong2'})
    assert b'Too many incorrect attempts' in resp.data
    assert key not in secrets_store

# Test expiration
def test_expiration(client):
    clear_store()
    client.post('/', data={
        'message': 'expire',
        'pin': '54321',
        'exp': '0',  # 0 minutes, expires immediately
        'exp_unit': 'minutes'
    })
    key = next(iter(secrets_store))
    # Simulate time passing
    secrets_store[key]['expire_at'] = int(time.time()) - 1
    resp = client.get(f'/combo/{key}')
    assert b'Secret not found or expired' in resp.data or b'expired' in resp.data
    assert key not in secrets_store

# Test PIN length validation
def test_pin_length(client):
    clear_store()
    resp = client.post('/', data={
        'message': 'short pin',
        'pin': '123',
        'exp': '1',
        'exp_unit': 'minutes'
    })
    assert b'PIN must be 5 characters' in resp.data

# Test missing fields
def test_missing_fields(client):
    clear_store()
    resp = client.post('/', data={
        'message': '',
        'pin': '',
        'exp': '',
        'exp_unit': 'minutes'
    })
    assert b'All fields are required' in resp.data

def test_file_upload_download(client):
    # Simulate chunked upload of a small file
    pin = '54321'
    exp = '1'
    exp_unit = 'minutes'
    filename = 'test.txt'
    content = b'hello file secret'
    key = None
    chunk_size = 5  # bytes, for test
    total_chunks = (len(content) + chunk_size - 1) // chunk_size
    # Start upload
    for idx in range(total_chunks):
        chunk = content[idx*chunk_size:(idx+1)*chunk_size]
        form = {
            'filename': filename,
            'iv': 'AAAAAAAAAAAA',  # dummy IV (not used for test decryption)
            'chunk_idx': str(idx),
            'total_chunks': str(total_chunks),
            'file_size': str(len(content)),
            'pin': pin,
            'exp': exp,
            'exp_unit': exp_unit
        }
        data = {'chunk': (io.BytesIO(chunk), filename)}
        resp = client.post('/upload', data={**form, **data}, content_type='multipart/form-data')
        assert resp.status_code == 200
        key = resp.get_json()['key']
    # Check /created page
    resp = client.get(f'/created?key={key}')
    assert b'test.txt' in resp.data or b'files.zip' in resp.data
    # Try to download with wrong PIN
    resp = client.post(f'/download/{key}/{filename}', data={'pin': 'wrongpin'})
    assert b'Incorrect PIN' in resp.data
    # Download with correct PIN
    resp = client.post(f'/download/{key}/{filename}', data={'pin': pin})
    assert resp.status_code == 200
    assert resp.data  # Should return file content (encrypted)
    # After download, file should be destroyed
    resp = client.post(f'/download/{key}/{filename}', data={'pin': pin})
    assert b'File not found or expired' in resp.data 

def test_text_only_secret(client):
    clear_store()
    resp = client.post('/', data={
        'message': 'just text',
        'pin': '12345',
        'exp': '1',
        'exp_unit': 'minutes'
    })
    key = next(iter(secrets_store))
    resp = client.get(f'/created?key={key}')
    assert b'just text' in resp.data  # secret text should now be shown on created page
    assert b'Copy Link' in resp.data or b'Share this link' in resp.data
    assert b'/combo/' in resp.data  # the share link should be present

def test_file_only_secret(client):
    clear_store()
    pin = '54321'
    exp = '1'
    exp_unit = 'minutes'
    filename = 'file.txt'
    content = b'file content'
    chunk_size = 5
    total_chunks = (len(content) + chunk_size - 1) // chunk_size
    key = None
    for idx in range(total_chunks):
        chunk = content[idx*chunk_size:(idx+1)*chunk_size]
        form = {
            'filename': filename,
            'iv': 'AAAAAAAAAAAA',
            'chunk_idx': str(idx),
            'total_chunks': str(total_chunks),
            'file_size': str(len(content)),
            'pin': pin,
            'exp': exp,
            'exp_unit': exp_unit
        }
        data = {'chunk': (io.BytesIO(chunk), filename)}
        resp = client.post('/upload', data={**form, **data}, content_type='multipart/form-data')
        assert resp.status_code == 200
        key = resp.get_json()['key']
    resp = client.get(f'/created?key={key}')
    assert b'file.txt' in resp.data
    assert b'Copy Link' in resp.data
    assert b'/download/' in resp.data

def test_text_and_file_secret(client):
    clear_store()
    # First, create a text+file secret via the main form
    data = {
        'message': 'combo secret',
        'pin': '99999',
        'exp': '1',
        'exp_unit': 'minutes'
    }
    # Simulate file upload
    file_data = {'files': (io.BytesIO(b'combo file'), 'combo.txt')}
    resp = client.post('/', data={**data, **file_data}, content_type='multipart/form-data')
    key = next(iter(secrets_store))
    resp = client.get(f'/created?key={key}')
    assert b'combo.txt' in resp.data
    assert b'Copy Link' in resp.data
    assert b'/download/' in resp.data 

def test_chunked_upload_with_message(client):
    clear_store()
    pin = '88888'
    exp = '1'
    exp_unit = 'minutes'
    filename = 'withmsg.txt'
    content = b'file with secret text'
    secret_text = 'this is the secret text!'
    chunk_size = 5
    total_chunks = (len(content) + chunk_size - 1) // chunk_size
    key = None
    for idx in range(total_chunks):
        chunk = content[idx*chunk_size:(idx+1)*chunk_size]
        form = {
            'filename': filename,
            'iv': 'AAAAAAAAAAAA',
            'chunk_idx': str(idx),
            'total_chunks': str(total_chunks),
            'file_size': str(len(content)),
            'pin': pin,
            'exp': exp,
            'exp_unit': exp_unit,
            'message': secret_text if idx == 0 else ''  # Only send message on first chunk
        }
        data = {'chunk': (io.BytesIO(chunk), filename)}
        resp = client.post('/upload', data={**form, **data}, content_type='multipart/form-data')
        assert resp.status_code == 200
        key = resp.get_json()['key']
    # Download with correct PIN, should show both file and secret text
    resp = client.post(f'/download/{key}/{filename}', data={'pin': pin})
    assert b'file with secret text' not in resp.data  # file content is not shown directly
    assert b'this is the secret text!' in resp.data  # secret text should be shown
    assert b'withmsg.txt' in resp.data  # file name should be shown 