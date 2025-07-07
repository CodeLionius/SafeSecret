import os
import pytest
from app import app, secrets_store, fernet
import time

@pytest.fixture
def client():
    app.config['TESTING'] = True
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
    assert b'Secret Link Created' in resp.data
    # Extract key from the link
    for k in secrets_store:
        key = k
        break
    # Access secret page (GET)
    resp = client.get(f'/secret/{key}')
    assert b'Enter PIN' in resp.data
    # Submit correct PIN
    resp = client.post(f'/secret/{key}', data={'pin': '12345'})
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
        resp = client.post(f'/secret/{key}', data={'pin': 'wrong1'})
        assert b'Incorrect PIN' in resp.data
    # 3rd wrong attempt destroys secret
    resp = client.post(f'/secret/{key}', data={'pin': 'wrong2'})
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
    resp = client.get(f'/secret/{key}')
    assert b'Secret not found or expired' in resp.data
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