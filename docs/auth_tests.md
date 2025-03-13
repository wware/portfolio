# Test-driven development for the Auth stuff

This describes a plan to do TDD on [the auth stuff](auth.md).

> I'm a big fan of test-driven development, and I'd like help in designing a sequence of tests as I incrementally implement some of these ideas. This would be in a development environment using pytest. The first suite of tests would be to make sure HTTPS is set up and working correctly. The second would be to test user registration and the whole passkey workflow, using some kind of mock of the client hardware (ubikey or whatever). The third would be to create a time-limited API token and check that it is handled correctly, and test that the revocation of the token also works correctly. Let's plan on a file-based SQLite database for anything we need to persist. Does all that make sense?

This sounds like an excellent approach to implementing WebAuthn with a test-driven methodology. Let me outline a testing strategy for each of your three focus areas.

## 1. Testing HTTPS Setup

For testing HTTPS in a development environment:

<details>
    <summary>HTTPS tests</summary>

```python
import pytest
import requests
import ssl
from urllib.parse import urlparse

# Configure base URL for your application
BASE_URL = "https://localhost:8443"  # Adjust port as needed

@pytest.fixture
def https_session():
    """Create a requests session that accepts self-signed certificates for testing"""
    session = requests.Session()
    session.verify = False  # Warning: Only for development testing!
    requests.packages.urllib3.disable_warnings()  # Suppress insecure warnings
    return session

def test_https_connection(https_session):
    """Test basic HTTPS connection to the server"""
    response = https_session.get(f"{BASE_URL}/")
    assert response.status_code == 200
    
    # Verify we're using HTTPS
    assert urlparse(response.url).scheme == "https"

def test_https_redirect(https_session):
    """Test HTTP to HTTPS redirect if implemented"""
    http_url = BASE_URL.replace("https://", "http://")
    response = https_session.get(http_url, allow_redirects=True)
    assert response.status_code == 200
    assert urlparse(response.url).scheme == "https"

def test_ssl_certificate():
    """Test SSL certificate information"""
    hostname = urlparse(BASE_URL).hostname
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # For self-signed certs in development
    
    with context.wrap_socket(socket.socket(), server_hostname=hostname) as s:
        s.connect((hostname, urlparse(BASE_URL).port or 443))
        cert = s.getpeercert(binary_form=True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
        
        # Basic certificate checks
        subject = dict(x509.get_subject().get_components())
        assert b'CN' in subject  # Common Name exists
        # Add more certificate checks as needed
```
</details>

## 2. Testing WebAuthn User Registration/Authentication

For WebAuthn testing, we'll use `webauthn-mocks` library to simulate authenticator hardware:

<details>
    <summary>User Registration/Authentication</summary>

```python
import pytest
import json
import base64
from fastapi.testclient import TestClient
from webauthn.helpers.structs import AuthenticationCredential, RegistrationCredential
from your_app.main import app  # Import your FastAPI app
from unittest.mock import patch, MagicMock

# SQLite setup
import sqlite3

@pytest.fixture
def db():
    """Set up a test SQLite database"""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    # Create necessary tables
    cursor.execute('''
    CREATE TABLE users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    cursor.execute('''
    CREATE TABLE credentials (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        public_key BLOB,
        sign_count INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')
    conn.commit()
    yield conn
    conn.close()

@pytest.fixture
def client():
    """Create a test client for the FastAPI app"""
    return TestClient(app)

# Mock WebAuthn registration
def test_registration_flow(client, db):
    """Test the complete WebAuthn registration flow with mocked authenticator"""
    username = "test_user"
    
    # Step 1: Start registration
    response = client.post("/register/start", json={"username": username})
    assert response.status_code == 200
    
    reg_data = response.json()
    assert "challenge" in reg_data
    
    # Step 2: Mock the authenticator response
    # In real testing, use the webauthn-mocks library to generate realistic credentials
    mock_credential = {
        "id": "test_credential_id",
        "rawId": base64.urlsafe_b64encode(b"test_raw_id").decode('ascii'),
        "type": "public-key",
        "response": {
            "clientDataJSON": base64.urlsafe_b64encode(json.dumps({
                "type": "webauthn.create",
                "challenge": reg_data["challenge"],
                "origin": "https://localhost:8443"
            }).encode()).decode('ascii'),
            "attestationObject": base64.urlsafe_b64encode(b"mock_attestation_obj").decode('ascii')
        }
    }
    
    # Patch the verify_registration_response function
    with patch('webauthn.verify_registration_response') as mock_verify:
        # Configure the mock to return a successful verification
        mock_verification = MagicMock()
        mock_verification.credential_id = "test_credential_id"
        mock_verification.credential_public_key = b"mock_public_key"
        mock_verification.sign_count = 0
        mock_verify.return_value = mock_verification
        
        # Step 3: Complete registration
        response = client.post("/register/complete", json={
            "username": username,
            "credential": mock_credential
        })
        
        assert response.status_code == 200
        assert response.json()["status"] == "success"
    
    # Verify user was added to database
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    assert cursor.fetchone() is not None
    
    # Verify credential was stored
    cursor.execute("SELECT * FROM credentials")
    assert cursor.fetchone() is not None

# Mock WebAuthn authentication
def test_authentication_flow(client, db):
    """Test the WebAuthn authentication flow with mocked authenticator"""
    # First, ensure we have a registered user
    # [Setup code to insert test user and credential in the database]
    
    username = "test_user"
    
    # Step 1: Start authentication
    response = client.post("/login/start", json={"username": username})
    assert response.status_code == 200
    
    auth_data = response.json()
    assert "challenge" in auth_data
    
    # Step 2: Mock the authenticator response
    mock_credential = {
        "id": "test_credential_id",
        "rawId": base64.urlsafe_b64encode(b"test_raw_id").decode('ascii'),
        "type": "public-key",
        "response": {
            "clientDataJSON": base64.urlsafe_b64encode(json.dumps({
                "type": "webauthn.get",
                "challenge": auth_data["challenge"],
                "origin": "https://localhost:8443"
            }).encode()).decode('ascii'),
            "authenticatorData": base64.urlsafe_b64encode(b"mock_auth_data").decode('ascii'),
            "signature": base64.urlsafe_b64encode(b"mock_signature").decode('ascii'),
            "userHandle": base64.urlsafe_b64encode(b"user_handle").decode('ascii')
        }
    }
    
    # Patch the verify_authentication_response function
    with patch('webauthn.verify_authentication_response') as mock_verify:
        # Configure the mock
        mock_verification = MagicMock()
        mock_verification.new_sign_count = 1
        mock_verify.return_value = mock_verification
        
        # Step 3: Complete authentication
        response = client.post("/login/complete", json={
            "username": username,
            "credential": mock_credential
        })
        
        assert response.status_code == 200
        result = response.json()
        assert result["status"] == "success"
        assert "access_token" in result
```
</details>

## 3. Testing JWT Token Creation and Revocation

<details>
    <summary>JWT Token Creation and Revocation</summary>

```python
import pytest
import jwt
import time
from datetime import datetime, timedelta
from fastapi.testclient import TestClient

@pytest.fixture
def authenticated_client(client):
    """Create an authenticated client with a valid token"""
    # [Setup code to create and authenticate a test user]
    response = client.post("/login/complete", json={
        "username": "test_user",
        "credential": {...}  # Mock credential
    })
    token_data = response.json()
    
    # Create a client with the token in headers
    auth_client = TestClient(app)
    auth_client.headers.update({"Authorization": f"Bearer {token_data['access_token']}"})
    
    # Return both the client and the raw token for tests
    return auth_client, token_data['access_token']

def test_token_creation():
    """Test JWT token creation"""
    # This can be a unit test for your token creation function
    from your_app.main import create_access_token
    
    test_data = {"sub": "test_user"}
    token, expire = create_access_token(test_data)
    
    # Verify token can be decoded
    from your_app.main import JWT_SECRET, TOKEN_ALGORITHM
    decoded = jwt.decode(token, JWT_SECRET, algorithms=[TOKEN_ALGORITHM])
    
    assert decoded["sub"] == "test_user"
    assert "exp" in decoded
    # Assert expiration is in the future
    assert datetime.fromtimestamp(decoded["exp"]) > datetime.utcnow()

def test_protected_endpoint(authenticated_client):
    """Test accessing a protected endpoint with a valid token"""
    client, _ = authenticated_client
    response = client.get("/api/protected-data")
    
    assert response.status_code == 200
    assert "secret_value" in response.json()["data"]

def test_token_expiration():
    """Test that expired tokens are rejected"""
    # Create a token that expires immediately
    from your_app.main import create_access_token, JWT_SECRET, TOKEN_ALGORITHM
    
    test_data = {"sub": "test_user"}
    token, _ = create_access_token(
        test_data, 
        expires_delta=timedelta(seconds=1)  # Token expires in 1 second
    )
    
    # Wait for token to expire
    time.sleep(2)
    
    # Try to use the expired token
    client = TestClient(app)
    client.headers.update({"Authorization": f"Bearer {token}"})
    response = client.get("/api/protected-data")
    
    # Should be rejected
    assert response.status_code == 401

def test_token_revocation(authenticated_client, client):
    """Test revoking a token"""
    auth_client, token = authenticated_client
    
    # First verify token works
    response = auth_client.get("/api/protected-data")
    assert response.status_code == 200
    
    # Revoke token
    response = auth_client.post("/token/revoke")
    assert response.status_code == 200
    
    # Try to use the revoked token
    response = auth_client.get("/api/protected-data")
    assert response.status_code == 401  # Should be unauthorized
```
</details>

## Setting Up SQLite Database

For the SQLite integration, you'll need to create a database manager:

<details>
    <summary>Setting Up SQLite Database</summary>

```python
# db.py
import sqlite3
import os
from contextlib import contextmanager

DB_PATH = os.environ.get("TEST_DB_PATH", "webauthn_test.db")

def init_db():
    """Initialize the database with required tables"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create credentials table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            public_key BLOB,
            sign_count INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        ''')
        
        # Create revoked_tokens table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS revoked_tokens (
            token TEXT PRIMARY KEY,
            revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        conn.commit()

@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn
    finally:
        conn.close()
```
</details>


## Pytest Configuration

Create a `conftest.py` file to set up your test environment:

<details>
    <summary>Pytest Configuration</summary>

```python
# conftest.py
import pytest
import os
import tempfile
from your_app.db import init_db

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Set up a test database for the testing session"""
    # Create a temporary file for the test database
    db_fd, db_path = tempfile.mkstemp()
    os.environ["TEST_DB_PATH"] = db_path
    
    # Initialize the database
    init_db()
    
    yield
    
    # Clean up
    os.close(db_fd)
    os.unlink(db_path)
```
</details>

This test plan provides a comprehensive approach to incrementally testing your WebAuthn implementation with FastAPI. The mocking strategy allows you to test WebAuthn functionality without actual hardware authenticators, and the SQLite database provides a simple persistence layer for your tests.
