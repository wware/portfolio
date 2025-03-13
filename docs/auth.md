# Passkeys and WebAuthn Authentication

> Assume I have a website built with FastAPI. I want to add WebAuthn authentication but I'm new to that technology. Can you please explain it simply, what it looks like from the user's pov, and how to implement it on the server?

## WebAuthn Explained Simply

WebAuthn (Web Authentication) is a modern, secure way for users to log into websites without passwords. Instead, it uses "authenticators" like:

- Biometrics (fingerprint/face recognition)
- Security keys (like YubiKeys)
- Device-based authentication (like Windows Hello)

These are either biometric or they depend on a piece of hardware.

### Key Concepts

1. **Registration Flow**:
    - Server creates a challenge and options
    - Browser prompts user to use authenticator
    - Server verifies and stores credential

2. **Login Flow**:
    - Server sends challenge and allowed credentials
    - Browser prompts for authentication
    - Server verifies and grants access

3. **Security Benefits**:
    - No passwords to steal or forget
    - Resistant to phishing (domain verification)
    - Protected by hardware/biometrics

4. **Implementation Notes**:
    - For production, use a proper database
    - Add HTTPS (required in production)
    - Consider user experience for different devices

## From a User's Perspective

When a user registers on your site with WebAuthn:

1. They enter a username
2. Instead of creating a password, they're prompted to use an authenticator (e.g., "Touch your fingerprint sensor")
3. They complete the verification (touch fingerprint, insert security key, etc.)
4. Registration complete!

When they log in later:

1. They enter their username
2. They're prompted to use the same authenticator
3. After verification, they're instantly logged in

Users experience this as a quick, password-free login that feels more secure and convenient.

## Implementing WebAuthn in FastAPI

### How to add WebAuthn to your FastAPI site:

<details>
    <summary>Server side code in Python</summary>

```python
"""
WebAuthn Implementation with FastAPI

This example demonstrates how to implement WebAuthn (Web Authentication) in a FastAPI application.
It provides endpoints for registration and authentication using WebAuthn.
"""

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import webauthn
from webauthn.helpers.structs import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    RegistrationCredential,
    AuthenticationCredential,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from pydantic import BaseModel
import base64
import json
import secrets
from typing import Dict, Optional, List
import uuid

# Initialize FastAPI
app = FastAPI(title="FastAPI WebAuthn Example")

# This would be your database in a real application
users_db = {}
credentials_db = {}

# Store challenges temporarily (in a real app, use Redis or similar)
challenge_db = {}

# Configuration for your application
RELYING_PARTY_ID = "localhost"  # Your domain name
RELYING_PARTY_NAME = "FastAPI WebAuthn Example"
RELYING_PARTY_ORIGIN = "http://localhost:8000"  # Your origin URL

# Pydantic models for request validation
class RegisterStartRequest(BaseModel):
    username: str

class RegisterCompleteRequest(BaseModel):
    username: str
    credential: dict

class LoginStartRequest(BaseModel):
    username: str

class LoginCompleteRequest(BaseModel):
    username: str
    credential: dict

# Utility functions
def generate_challenge() -> str:
    """Generate a random challenge for WebAuthn operations"""
    random_bytes = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')

# API Endpoints
@app.post("/register/start")
async def register_start(request: RegisterStartRequest):
    """Start the registration process"""
    # Check if user already exists
    if request.username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Generate a new user ID
    user_id = str(uuid.uuid4())
    
    # Store the user (in a real app, you'd save to a database)
    users_db[request.username] = {
        "id": user_id,
        "username": request.username,
        "credentials": []
    }
    
    # Generate a challenge
    challenge = generate_challenge()
    challenge_db[request.username] = challenge
    
    # Create WebAuthn registration options
    options = PublicKeyCredentialCreationOptions(
        rp_id=RELYING_PARTY_ID,
        rp_name=RELYING_PARTY_NAME,
        user_id=user_id,
        user_name=request.username,
        user_display_name=request.username,
        challenge=challenge,
        pubkey_cred_params=[
            {"type": "public-key", "alg": COSEAlgorithmIdentifier.ES256},
            {"type": "public-key", "alg": COSEAlgorithmIdentifier.RS256},
        ],
        timeout=60000,
        attestation="direct",
        authenticator_selection={
            "authenticator_attachment": "platform",  # or "cross-platform" for security keys
            "require_resident_key": False,
            "user_verification": "preferred",
        },
        exclude_credentials=[],  # No credentials to exclude for a new user
    )
    
    return options.model_dump(mode="json")

@app.post("/register/complete")
async def register_complete(request: RegisterCompleteRequest):
    """Complete the registration process"""
    username = request.username
    
    # Check if user exists
    if username not in users_db:
        raise HTTPException(status_code=400, detail="User does not exist")
    
    # Get the challenge
    challenge = challenge_db.get(username)
    if not challenge:
        raise HTTPException(status_code=400, detail="No challenge found")
    
    # Parse the credential
    try:
        credential = RegistrationCredential.model_validate(request.credential)
        
        # Verify the registration
        registration_verification = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=RELYING_PARTY_ORIGIN,
            expected_rp_id=RELYING_PARTY_ID,
            require_user_verification=False,
        )
        
        # Store the credential
        credential_id = registration_verification.credential_id
        public_key = registration_verification.credential_public_key
        
        # In a real app, store these in a secure database
        credentials_db[credential_id] = {
            "username": username,
            "public_key": public_key,
            "sign_count": registration_verification.sign_count,
        }
        
        # Associate credential with user
        users_db[username]["credentials"].append(credential_id)
        
        # Clean up the challenge
        del challenge_db[username]
        
        return {"status": "success", "message": "Registration successful"}
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Registration failed: {str(e)}")

@app.post("/login/start")
async def login_start(request: LoginStartRequest):
    """Start the login process"""
    username = request.username
    
    # Check if user exists
    if username not in users_db:
        raise HTTPException(status_code=400, detail="User does not exist")
    
    # Get user's credentials
    user_credential_ids = users_db[username]["credentials"]
    if not user_credential_ids:
        raise HTTPException(status_code=400, detail="No credentials found for user")
    
    # Create a list of allowed credentials
    allowed_credentials = []
    for cred_id in user_credential_ids:
        allowed_credentials.append({
            "type": "public-key",
            "id": cred_id,
        })
    
    # Generate a challenge
    challenge = generate_challenge()
    challenge_db[username] = challenge
    
    # Create WebAuthn authentication options
    options = PublicKeyCredentialRequestOptions(
        challenge=challenge,
        timeout=60000,
        rp_id=RELYING_PARTY_ID,
        allow_credentials=allowed_credentials,
        user_verification="preferred",
    )
    
    return options.model_dump(mode="json")

@app.post("/login/complete")
async def login_complete(request: LoginCompleteRequest):
    """Complete the login process"""
    username = request.username
    
    # Check if user exists
    if username not in users_db:
        raise HTTPException(status_code=400, detail="User does not exist")
    
    # Get the challenge
    challenge = challenge_db.get(username)
    if not challenge:
        raise HTTPException(status_code=400, detail="No challenge found")
    
    # Parse the credential
    try:
        credential = AuthenticationCredential.model_validate(request.credential)
        
        # Get credential data
        credential_id = credential.id
        cred_data = credentials_db.get(credential_id)
        if not cred_data or cred_data["username"] != username:
            raise HTTPException(status_code=400, detail="Invalid credential")
        
        # Verify the authentication
        auth_verification = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=RELYING_PARTY_ORIGIN,
            expected_rp_id=RELYING_PARTY_ID,
            credential_public_key=cred_data["public_key"],
            credential_current_sign_count=cred_data["sign_count"],
            require_user_verification=False,
        )
        
        # Update the sign count
        credentials_db[credential_id]["sign_count"] = auth_verification.new_sign_count
        
        # Clean up the challenge
        del challenge_db[username]
        
        # In a real app, you would create a session or JWT token here
        
        return {"status": "success", "message": "Login successful"}
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Authentication failed: {str(e)}")

# Serve a simple HTML page for testing
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Run the application with: uvicorn main:app --reload
```

</details>

### Sample client-side implementation

<details>
    <summary>Client side code in HTML and JavaScript</summary>

```
<!-- 
templates/index.html
This is a simple client-side implementation of WebAuthn for your FastAPI application.
Place this file in a 'templates' directory in your FastAPI project.
-->

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebAuthn Example</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        .container {
            display: flex;
            justify-content: space-between;
        }
        .panel {
            flex: 1;
            margin: 10px;
            padding: 20px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        button {
            margin-top: 10px;
            padding: 8px 16px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background-color: #45a049;
        }
        input {
            width: 100%;
            padding: 8px;
            margin-bottom: 10px;
            box-sizing: border-box;
        }
        .status {
            margin-top: 20px;
            padding: 10px;
            border-radius: 4px;
        }
        .success {
            background-color: #dff0d8;
            color: #3c763d;
        }
        .error {
            background-color: #f2dede;
            color: #a94442;
        }
    </style>
</head>
<body>
    <h1>WebAuthn Example</h1>
    
    <div class="container">
        <div class="panel">
            <h2>Register</h2>
            <div>
                <label for="register-username">Username:</label>
                <input type="text" id="register-username" placeholder="Enter username">
                <button id="register-button">Register</button>
            </div>
            <div id="register-status" class="status"></div>
        </div>
        
        <div class="panel">
            <h2>Login</h2>
            <div>
                <label for="login-username">Username:</label>
                <input type="text" id="login-username" placeholder="Enter username">
                <button id="login-button">Login</button>
            </div>
            <div id="login-status" class="status"></div>
        </div>
    </div>
    
    <script>
        // Helper functions for encoding/decoding base64url
        function base64UrlToBuffer(base64Url) {
            const padding = '='.repeat((4 - (base64Url.length % 4)) % 4);
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/') + padding;
            const binary = window.atob(base64);
            const buffer = new ArrayBuffer(binary.length);
            const view = new Uint8Array(buffer);
            for (let i = 0; i < binary.length; i++) {
                view[i] = binary.charCodeAt(i);
            }
            return buffer;
        }
        
        function bufferToBase64Url(buffer) {
            const bytes = new Uint8Array(buffer);
            let str = '';
            for (const byte of bytes) {
                str += String.fromCharCode(byte);
            }
            const base64 = window.btoa(str);
            return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }
        
        // ------ Registration Functions ------
        async function startRegistration() {
            const username = document.getElementById('register-username').value;
            if (!username) {
                updateStatus('register-status', 'Please enter a username', 'error');
                return;
            }
            
            try {
                // Call the registration start endpoint
                const response = await fetch('/register/start', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username }),
                });
                
                if (!response.ok) {
                    throw new Error(`Registration start failed: ${response.statusText}`);
                }
                
                // Get the options from the server
                const options = await response.json();
                
                // Convert base64url strings to ArrayBuffers
                options.challenge = base64UrlToBuffer(options.challenge);
                options.user.id = base64UrlToBuffer(options.user.id);
                if (options.excludeCredentials) {
                    for (const cred of options.excludeCredentials) {
                        cred.id = base64UrlToBuffer(cred.id);
                    }
                }
                
                // Create credentials
                const credential = await navigator.credentials.create({
                    publicKey: options
                });
                
                // Complete the registration
                await completeRegistration(username, credential);
                
            } catch (error) {
                updateStatus('register-status', `Error: ${error.message}`, 'error');
                console.error('Registration error:', error);
            }
        }
        
        async function completeRegistration(username, credential) {
            // Convert the credential to JSON
            const credentialJSON = {
                id: credential.id,
                rawId: bufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
                    attestationObject: bufferToBase64Url(credential.response.attestationObject),
                }
            };
            
            // Call the registration complete endpoint
            const response = await fetch('/register/complete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username,
                    credential: credentialJSON
                }),
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(`Registration failed: ${errorData.detail || response.statusText}`);
            }
            
            const result = await response.json();
            updateStatus('register-status', 'Registration successful!', 'success');
        }
        
        // ------ Login Functions ------
        async function startLogin() {
            const username = document.getElementById('login-username').value;
            if (!username) {
                updateStatus('login-status', 'Please enter a username', 'error');
                return;
            }
            
            try {
                // Call the login start endpoint
                const response = await fetch('/login/start', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username }),
                });
                
                if (!response.ok) {
                    throw new Error(`Login start failed: ${response.statusText}`);
                }
                
                // Get the options from the server
                const options = await response.json();
                
                // Convert base64url strings to ArrayBuffers
                options.challenge = base64UrlToBuffer(options.challenge);
                if (options.allowCredentials) {
                    for (const cred of options.allowCredentials) {
                        cred.id = base64UrlToBuffer(cred.id);
                    }
                }
                
                // Get credentials
                const credential = await navigator.credentials.get({
                    publicKey: options
                });
                
                // Complete the login
                await completeLogin(username, credential);
                
            } catch (error) {
                updateStatus('login-status', `Error: ${error.message}`, 'error');
                console.error('Login error:', error);
            }
        }
        
        async function completeLogin(username, credential) {
            // Convert the credential to JSON
            const credentialJSON = {
                id: credential.id,
                rawId: bufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
                    authenticatorData: bufferToBase64Url(credential.response.authenticatorData),
                    signature: bufferToBase64Url(credential.response.signature),
                    userHandle: credential.response.userHandle ? bufferToBase64Url(credential.response.userHandle) : null,
                }
            };
            
            // Call the login complete endpoint
            const response = await fetch('/login/complete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username,
                    credential: credentialJSON
                }),
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(`Login failed: ${errorData.detail || response.statusText}`);
            }
            
            const result = await response.json();
            updateStatus('login-status', 'Login successful!', 'success');
        }
        
        // Helper function to update status messages
        function updateStatus(elementId, message, type) {
            const statusElement = document.getElementById(elementId);
            statusElement.textContent = message;
            statusElement.className = 'status ' + type;
        }
        
        // Add event listeners
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('register-button').addEventListener('click', startRegistration);
            document.getElementById('login-button').addEventListener('click', startLogin);
        });
    </script>
</body>
</html>
```

</details>

## Setting Up Your Project

1. First, install required packages:

```bash
pip install fastapi uvicorn webauthn-python pydantic jinja2
```

2. Create the project structure:

```
your_project/
├── main.py            # FastAPI backend code
└── templates/
    └── index.html     # Frontend HTML/JS
```

3. Copy the backend code to `main.py` and the frontend code to `templates/index.html`.

4. Run the application:

```bash
uvicorn main:app --reload
```

5. Visit `http://localhost:8000` in your browser to test.



## Security Keys: More Than Just Storage

> For a webauthn client that is not using biometrics, is there some hardware secret sauce required? or is it just the designated locus for the private key?

Your question gets right to the heart of what makes WebAuthn security keys special. It's not just about storing the private key - there's indeed some "hardware secret sauce" involved.

### The Key Security Features

Security keys (like YubiKeys, Google Titan keys, etc.) have several crucial security properties:

* **Secure Element**: They contain a tamper-resistant secure element (specialized microchip) that:
    - Generates and stores cryptographic keys
    - Performs cryptographic operations inside the chip
    - Prevents the private key from ever being exported or extracted

* **User Presence Verification**: The physical button/touch sensor isn't just for show:
    - Ensures a human is present during each authentication
    - Prevents remote malware from silently using the key
    - Creates a physical action requirement for each authentication

* **Counter Mechanism**: Keys maintain an internal counter that:
    - Increments with each use
    - Helps detect cloned authenticators
    - Allows servers to identify replay attacks

* **Origin Binding**: The key cryptographically ties authentication to specific websites:
    - Prevents phishing by binding credentials to the correct domain
    - Stops credentials generated for one site from being used on another

### The Real "Secret Sauce"

The most important aspect is that the private key **cannot be extracted** - even by the device owner. All cryptographic operations happen inside the secure element. This means:

1. The private key never leaves the device
2. The key cannot be copied, backed up, or cloned
3. Malware on your computer cannot access the key
4. Even sophisticated hardware attacks are extremely difficult

This hardware-enforced key isolation is what differentiates a WebAuthn security key from software-based approaches where private keys might be vulnerable to extraction.

### Non-Biometric Authentication Flow

Without biometrics, the authentication flow is:

1. Website challenges the security key
2. User proves physical presence by touching the key
3. Key performs the cryptographic operation internally
4. Key returns only the signed challenge (never the private key)

So yes - the security key is far more than just a designated place to store a private key. It's a specialized cryptographic device with hardware-based security controls that create a trusted, phishing-resistant authentication mechanism.



## Implementing API Tokens with WebAuthn

> Once a user has registered, I would like the server to be able to issue a time-limited API token which could be used by client side scripts that want to make API calls. Is that good security practice? How would that be implemented on the server side?

Yes, issuing time-limited API tokens after WebAuthn authentication is a good security practice. This approach follows the principle of "authenticate heavily once, then use lighter verification for a limited time" - similar to how modern authentication systems work.

### Security Benefits

- **Separation of concerns**: Strong authentication (WebAuthn) is separate from API authorization (tokens)
- **Limited exposure**: Short-lived tokens reduce the risk if intercepted
- **Revocable access**: You can invalidate tokens if needed without requiring re-authentication
- **Reduced authentication burden**: Users don't need to repeatedly use their authenticator

### Implementation Approach

#### Server side

<details>
    <summary>Python code</summary>

```python
"""
API Token Implementation with FastAPI and WebAuthn

This code extends the WebAuthn implementation to include API token generation,
validation, and usage for authenticated users.
"""

from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from datetime import datetime, timedelta
import secrets
from typing import Optional, Dict, List
from pydantic import BaseModel

# Include all the imports and WebAuthn code from the previous example
# ...

# Token configuration
JWT_SECRET = secrets.token_urlsafe(32)  # Generate a secure random key for JWT signing
TOKEN_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Short-lived tokens for security

# Token database (in a real app, use Redis or similar)
token_blacklist = set()

# Token models
class Token(BaseModel):
    access_token: str
    token_type: str
    expires_at: datetime

class TokenData(BaseModel):
    username: str
    exp: datetime

# OAuth2 scheme for token authentication
security = HTTPBearer()

# Utility functions for tokens
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a new JWT token with expiration time"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=TOKEN_ALGORITHM)
    
    return encoded_jwt, expire

def verify_token(token: str) -> dict:
    """Verify a JWT token and return the payload"""
    try:
        # Check if token is blacklisted
        if token in token_blacklist:
            raise HTTPException(
                status_code=401, 
                detail="Token has been revoked"
            )
        
        # Decode and verify the token
        payload = jwt.decode(token, JWT_SECRET, algorithms=[TOKEN_ALGORITHM])
        username = payload.get("sub")
        
        if username is None:
            raise HTTPException(
                status_code=401, 
                detail="Invalid token payload"
            )
        
        # Check if user exists
        if username not in users_db:
            raise HTTPException(
                status_code=401, 
                detail="User does not exist"
            )
        
        return payload
    
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=401, 
            detail="Invalid token or token expired"
        )

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Dependency to get the current user from a token"""
    token = credentials.credentials
    payload = verify_token(token)
    
    username = payload.get("sub")
    return users_db.get(username)

# Modified login endpoint to include token generation
@app.post("/login/complete")
async def login_complete(request: LoginCompleteRequest):
    """Complete the login process and return an access token"""
    username = request.username
    
    # Check if user exists
    if username not in users_db:
        raise HTTPException(status_code=400, detail="User does not exist")
    
    # Get the challenge
    challenge = challenge_db.get(username)
    if not challenge:
        raise HTTPException(status_code=400, detail="No challenge found")
    
    # Parse the credential
    try:
        credential = AuthenticationCredential.model_validate(request.credential)
        
        # Get credential data
        credential_id = credential.id
        cred_data = credentials_db.get(credential_id)
        if not cred_data or cred_data["username"] != username:
            raise HTTPException(status_code=400, detail="Invalid credential")
        
        # Verify the authentication
        auth_verification = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=RELYING_PARTY_ORIGIN,
            expected_rp_id=RELYING_PARTY_ID,
            credential_public_key=cred_data["public_key"],
            credential_current_sign_count=cred_data["sign_count"],
            require_user_verification=False,
        )
        
        # Update the sign count
        credentials_db[credential_id]["sign_count"] = auth_verification.new_sign_count
        
        # Clean up the challenge
        del challenge_db[username]
        
        # Generate access token
        access_token, expire = create_access_token(
            data={"sub": username},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        return {
            "status": "success", 
            "message": "Login successful",
            "access_token": access_token,
            "token_type": "bearer",
            "expires_at": expire
        }
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Authentication failed: {str(e)}")

# New token endpoints
@app.post("/token/refresh")
async def refresh_token(user = Depends(get_current_user)):
    """Generate a new token with a fresh expiration time"""
    username = user["username"]
    
    # Generate a new access token
    access_token, expire = create_access_token(
        data={"sub": username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_at": expire
    }

@app.post("/token/revoke")
async def revoke_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Revoke a token by adding it to the blacklist"""
    token = credentials.credentials
    
    # Verify the token is valid before revoking
    verify_token(token)
    
    # Add to blacklist
    token_blacklist.add(token)
    
    return {"status": "success", "message": "Token revoked successfully"}

# Protected API route example
@app.get("/api/protected-data")
async def get_protected_data(user = Depends(get_current_user)):
    """Example protected API endpoint requiring a valid token"""
    return {
        "status": "success",
        "message": f"Hello {user['username']}, this is protected data",
        "data": {
            "secret_value": "This data is only accessible with a valid token",
            "timestamp": datetime.utcnow()
        }
    }

# Sample API for listing user credentials (admin only in a real app)
@app.get("/api/user/credentials")
async def get_user_credentials(user = Depends(get_current_user)):
    """Get all credentials registered for the current user"""
    username = user["username"]
    
    # Get credential IDs
    credential_ids = users_db[username]["credentials"]
    
    # Get credential details
    credentials = []
    for cred_id in credential_ids:
        cred_data = credentials_db.get(cred_id)
        if cred_data:
            credentials.append({
                "id": cred_id,
                "sign_count": cred_data["sign_count"],
                # Don't include the public key in the response for security
            })
    
    return {
        "username": username,
        "credential_count": len(credentials),
        "credentials": credentials
    }
```
</details>

#### Client side

<details>
    <summary>JavaScript code</summary>

```javascript
// Client-side JavaScript for handling API tokens
// Add this to your index.html file

// Token storage
let authToken = null;
let tokenExpiry = null;

// Utility function to safely store tokens
function storeToken(tokenData) {
    // Store the token in memory (for this session)
    authToken = tokenData.access_token;
    tokenExpiry = new Date(tokenData.expires_at);
    
    // Optional: Store in localStorage for persistent sessions
    // Note: LocalStorage is vulnerable to XSS, so use with caution
    localStorage.setItem('authToken', tokenData.access_token);
    localStorage.setItem('tokenExpiry', tokenData.expires_at);
    
    console.log(`Token stored. Expires at ${tokenExpiry}`);
}

// Check if token exists and is valid
function hasValidToken() {
    // If we don't have a token in memory, check localStorage
    if (!authToken && localStorage.getItem('authToken')) {
        authToken = localStorage.getItem('authToken');
        tokenExpiry = new Date(localStorage.getItem('tokenExpiry'));
    }
    
    // Check if we have a token and it's not expired
    if (authToken && tokenExpiry) {
        // Add a 30-second buffer to ensure token isn't about to expire
        const bufferTime = 30 * 1000; // 30 seconds in milliseconds
        const now = new Date();
        return now.getTime() + bufferTime < tokenExpiry.getTime();
    }
    
    return false;
}

// Clear token on logout
function clearToken() {
    authToken = null;
    tokenExpiry = null;
    localStorage.removeItem('authToken');
    localStorage.removeItem('tokenExpiry');
}

// Function to handle login and token acquisition
async function loginWithWebAuthn(username) {
    try {
        // Start the WebAuthn login process
        const startResponse = await fetch('/login/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username }),
        });
        
        if (!startResponse.ok) {
            throw new Error(`Login start failed: ${startResponse.statusText}`);
        }
        
        const options = await startResponse.json();
        
        // Convert base64url strings to ArrayBuffers
        options.challenge = base64UrlToBuffer(options.challenge);
        if (options.allowCredentials) {
            for (const cred of options.allowCredentials) {
                cred.id = base64UrlToBuffer(cred.id);
            }
        }
        
        // Request the credential from the authenticator
        const credential = await navigator.credentials.get({
            publicKey: options
        });
        
        // Convert credential for sending to server
        const credentialJSON = {
            id: credential.id,
            rawId: bufferToBase64Url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
                authenticatorData: bufferToBase64Url(credential.response.authenticatorData),
                signature: bufferToBase64Url(credential.response.signature),
                userHandle: credential.response.userHandle ? bufferToBase64Url(credential.response.userHandle) : null,
            }
        };
        
        // Complete the login and get token
        const completeResponse = await fetch('/login/complete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username,
                credential: credentialJSON
            }),
        });
        
        if (!completeResponse.ok) {
            const errorData = await completeResponse.json();
            throw new Error(`Login failed: ${errorData.detail || completeResponse.statusText}`);
        }
        
        // Get the token and store it
        const tokenData = await completeResponse.json();
        storeToken(tokenData);
        
        return {
            success: true,
            message: 'Login successful',
            tokenData
        };
    } catch (error) {
        console.error('Login error:', error);
        return {
            success: false,
            message: error.message
        };
    }
}

// Function to make authenticated API requests
async function fetchWithAuth(url, options = {}) {
    // Check if token is valid
    if (!hasValidToken()) {
        // No valid token, user needs to login again
        throw new Error('No valid authentication token. Please login again.');
    }
    
    // Add Authorization header to request
    const authOptions = {
        ...options,
        headers: {
            ...options.headers,
            'Authorization': `Bearer ${authToken}`
        }
    };
    
    // Make the authenticated request
    const response = await fetch(url, authOptions);
    
    // Handle 401 Unauthorized (token expired or invalid)
    if (response.status === 401) {
        clearToken();
        throw new Error('Authentication token expired or invalid. Please login again.');
    }
    
    return response;
}

// Sample function to refresh the token
async function refreshToken() {
    try {
        const response = await fetchWithAuth('/token/refresh', {
            method: 'POST'
        });
        
        if (!response.ok) {
            throw new Error('Failed to refresh token');
        }
        
        const tokenData = await response.json();
        storeToken(tokenData);
        
        return {
            success: true,
            message: 'Token refreshed successfully'
        };
    } catch (error) {
        console.error('Token refresh error:', error);
        return {
            success: false,
            message: error.message
        };
    }
}

// Sample function to logout and revoke token
async function logout() {
    if (hasValidToken()) {
        try {
            // Revoke the token on the server
            await fetchWithAuth('/token/revoke', {
                method: 'POST'
            });
        } catch (error) {
            console.error('Error revoking token:', error);
        }
    }
    
    // Clear token from storage regardless of server response
    clearToken();
    
    return {
        success: true,
        message: 'Logged out successfully'
    };
}

// Sample function to access a protected API endpoint
async function fetchProtectedData() {
    try {
        const response = await fetchWithAuth('/api/protected-data');
        
        if (!response.ok) {
            throw new Error(`API request failed: ${response.statusText}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('API request error:', error);
        return {
            success: false,
            message: error.message
        };
    }
}

// Add event listeners for demo buttons
document.addEventListener('DOMContentLoaded', function() {
    // Adding logout functionality
    const logoutButton = document.createElement('button');
    logoutButton.id = 'logout-button';
    logoutButton.textContent = 'Logout';
    logoutButton.addEventListener('click', async () => {
        const result = await logout();
        alert(result.message);
        // Update UI to reflect logged out state
        document.getElementById('token-info').textContent = 'Not logged in';
        document.getElementById('protected-data').textContent = '';
    });
    
    // Button to fetch protected data
    const dataButton = document.createElement('button');
    dataButton.id = 'fetch-data-button';
    dataButton.textContent = 'Fetch Protected Data';
    dataButton.addEventListener('click', async () => {
        try {
            const data = await fetchProtectedData();
            if (data.success !== false) {
                document.getElementById('protected-data').textContent = 
                    JSON.stringify(data, null, 2);
            } else {
                alert(data.message);
            }
        } catch (error) {
            alert('Error: ' + error.message);
        }
    });
    
    // Add new elements to page
    const container = document.querySelector('.container');
    
    // Create API test panel
    const apiPanel = document.createElement('div');
    apiPanel.className = 'panel';
    apiPanel.innerHTML = `
        <h2>API Access</h2>
        <div>
            <p>Token Status: <span id="token-info">Not logged in</span></p>
            <div id="api-buttons"></div>
            <h3>Protected Data:</h3>
            <pre id="protected-data"></pre>
        </div>
    `;
    
    container.appendChild(apiPanel);
    document.getElementById('api-buttons').appendChild(dataButton);
    document.getElementById('api-buttons').appendChild(logoutButton);
    
    // Update login success handler to also update token info
    const originalLoginButton = document.getElementById('login-button');
    originalLoginButton.removeEventListener('click', startLogin);
    originalLoginButton.addEventListener('click', async () => {
        const username = document.getElementById('login-username').value;
        if (!username) {
            updateStatus('login-status', 'Please enter a username', 'error');
            return;
        }
        
        const result = await loginWithWebAuthn(username);
        if (result.success) {
            updateStatus('login-status', 'Login successful!', 'success');
            document.getElementById('token-info').textContent = 
                `Logged in as ${username}. Token expires at ${new Date(result.tokenData.expires_at).toLocaleTimeString()}`;
        } else {
            updateStatus('login-status', `Error: ${result.message}`, 'error');
        }
    });
    
    // Check for existing token on page load
    if (hasValidToken()) {
        document.getElementById('token-info').textContent = 
            `Token valid until ${tokenExpiry.toLocaleTimeString()}`;
    }
});
```
</details>

### Key Components of the Implementation

* **Token Generation**:
    - After successful WebAuthn authentication, the server generates a JWT (JSON Web Token)
    - The token contains the username and expiration time
    - Tokens are signed with a secret key to prevent tampering

* **Token Management**:
    - **Storage**: Client stores tokens in memory and optionally in localStorage
    - **Validation**: Server verifies token signature and expiration
    - **Refresh**: Client can request a new token before expiration
    - **Revocation**: Server maintains a blacklist of revoked tokens

* **API Security Flow**:
    - User authenticates with WebAuthn
    - Server issues a short-lived token (30 minutes in the example)
    - Client includes token in Authorization header for API requests
    - Server validates token before processing the request

### Security Considerations

* **Token Lifetime**:
    - Shorter lifetimes (15-60 minutes) are more secure
    - Balance security with user experience

* **Token Storage**:
    - Memory storage (variables) is cleared when page refreshes
    - localStorage persists but is vulnerable to XSS attacks
    - Consider using HttpOnly cookies as an alternative

* **Token Revocation**:
    - Implement server-side blacklisting for immediate revocation
    - For large-scale applications, use Redis or similar for blacklist storage

* **JWT Claims**:
    - Include minimal necessary data (username/user ID)
    - Add additional claims like IP address or device fingerprint for extra security

### Implementation Steps

1. Add the JWT package to your project:
   ```bash
   pip install python-jose[cryptography]
   ```

2. Add the token generation to the login endpoint

3. Add middleware or dependencies to validate tokens

4. Create endpoints for token refresh and revocation

5. Update your client-side code to manage tokens

This approach gives you a robust authentication system combining the security benefits of WebAuthn for initial authentication with the convenience of API tokens for continued access.


## Setting Up HTTPS in FastAPI

Running FastAPI with HTTPS is essential for security, especially when implementing authentication like WebAuthn (which requires HTTPS except on localhost). Here's why:

1. **Data encryption** between client and server
2. **Authentication** of the server to clients
3. **Required for WebAuthn** in production environments
4. **Protection against** man-in-the-middle attacks

### Option 1: Using Uvicorn with SSL Certificates

The simplest approach is running Uvicorn (the ASGI server for FastAPI) with SSL certificates:

```bash
uvicorn main:app --ssl-keyfile=./key.pem --ssl-certfile=./cert.pem
```

You'll need:

- **key.pem**: The private key file
- **cert.pem**: The SSL certificate file

#### SSL Certificates for Development

<font color="red">THIS IS FOR DEVELOPMENT ONLY!</font> See notes about production below.

For development, you can create self-signed certificates using OpenSSL.
When running the OpenSSL commands, you'll be prompted for certificate information:

- Country Name (2 letter code)
- State or Province
- Locality Name (city)
- Organization Name
- Organizational Unit
- Common Name (IMPORTANT: use your domain name or localhost)
- Email Address

<details>
    <summary>How to create self-signed certificates</summary>

```bash
#!/bin/bash
# Generate a private key
openssl genrsa -out key.pem 2048

# Generate a certificate signing request (CSR)
openssl req -new -key key.pem -out csr.pem

# Generate a self-signed certificate (valid for 365 days)
openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out cert.pem

# Clean up the CSR file
rm csr.pem

echo "Self-signed certificate generated:"
echo "Private key: key.pem"
echo "Certificate: cert.pem"
```
</details>

#### SSL Certificates for Production

For a production environment, you'll want to obtain trusted SSL certificates that browsers will recognize without security warnings. Here are the best options:

##### Let's Encrypt (Recommended)

Let's Encrypt is a free, automated, and open certificate authority that provides trusted SSL certificates.

- Completely free
- Automated renewal process
- Trusted by all major browsers
- Easy to set up

How to get Let's Encrypt certificates:

1. **Install Certbot**:
   ```bash
   # On Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install certbot
   
   # For Nginx
   sudo apt-get install python3-certbot-nginx
   
   # For Apache
   sudo apt-get install python3-certbot-apache
   ```

2. **Generate certificates**:
   ```bash
   # With Nginx
   sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
   
   # With Apache
   sudo certbot --apache -d yourdomain.com -d www.yourdomain.com
   
   # Standalone (if no web server is running)
   sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com
   ```

3. **Set up auto-renewal**:
   ```bash
   # Test auto-renewal
   sudo certbot renew --dry-run
   
   # Certbot installs a cron job or systemd timer automatically
   ```

##### Commercial Certificate Authorities

If you prefer a paid option (often with extended validation or additional features):

1. **DigiCert**: Premium certificates with high browser trust
2. **Sectigo** (formerly Comodo): Cost-effective with multi-domain options
3. **GlobalSign**: Good for enterprise with managed services
4. **GoDaddy**: Popular with good integration if you already use their services

These typically cost $50-300 per year depending on the validation level and features.

##### Cloud Provider Certificates

If your application is hosted with a cloud provider:

1. **AWS Certificate Manager**: Free SSL certificates for AWS services
2. **Google Cloud Certificate Manager**: Free SSL certificates with Google Cloud
3. **Azure App Service**: Free certificates for Azure-hosted services

##### Domain Registrar Certificates

Many domain registrars now offer free or inexpensive SSL certificates:

1. **Cloudflare**: Free SSL with their CDN service
2. **Namecheap**: Affordable certificates bundled with domain registration

#### Important Considerations for Production

1. **Validity period**: Let's Encrypt certificates last 90 days and must be renewed
2. **Automation**: Set up automatic renewal to avoid expiration
3. **Certificate chain**: Ensure the full chain is included
4. **Key security**: Keep your private keys secure
5. **Monitoring**: Set up monitoring for certificate expiration

For most applications, Let's Encrypt is the ideal solution due to its ease of use, zero cost, and automated renewal process. The certificates are trusted by all major browsers and provide the same level of encryption as paid certificates.


### Option 2: Using FastAPI with HTTPS in Production Code

For more production-ready code, you can configure HTTPS directly in your application:

<details>
    <summary>FastAPI HTTPS configuration</summary>

```python
"""
HTTPS Configuration for FastAPI

This script demonstrates how to run FastAPI with HTTPS enabled
using Uvicorn programmatically.
"""

import uvicorn
from fastapi import FastAPI
import os
import argparse

# Create the FastAPI app
app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello, HTTPS World!"}

@app.get("/secure")
async def secure_endpoint():
    return {"message": "This endpoint is secure!"}

if __name__ == "__main__":
    # Set up command line arguments
    parser = argparse.ArgumentParser(description="Run FastAPI with HTTPS")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8443, help="Port to bind to")
    parser.add_argument(
        "--ssl-keyfile", 
        default="./key.pem", 
        help="SSL key file path"
    )
    parser.add_argument(
        "--ssl-certfile", 
        default="./cert.pem", 
        help="SSL certificate file path"
    )
    parser.add_argument(
        "--reload", 
        action="store_true", 
        help="Enable auto-reload for development"
    )
    args = parser.parse_args()
    
    # Verify SSL files exist
    if not os.path.isfile(args.ssl_keyfile):
        raise FileNotFoundError(f"SSL key file not found: {args.ssl_keyfile}")
    if not os.path.isfile(args.ssl_certfile):
        raise FileNotFoundError(f"SSL certificate file not found: {args.ssl_certfile}")
    
    # Configure and run Uvicorn with SSL
    uvicorn.run(
        "main:app",  # Replace with the actual path to your app
        host=args.host,
        port=args.port,
        ssl_keyfile=args.ssl_keyfile,
        ssl_certfile=args.ssl_certfile,
        reload=args.reload
    )
    
    # Run with:
    # python main.py --port=8443 --ssl-keyfile=./key.pem --ssl-certfile=./cert.pem
```
</details>

### Option 3: Production Setup with Reverse Proxy

For production environments, the recommended approach is to use a reverse proxy:

<details>
    <summary>Nginx reverse proxy configuration</summary>

```nginx
# /etc/nginx/sites-available/fastapi-app

server {
    # Listen on port 80 and redirect to HTTPS
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    # Redirect all HTTP requests to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    # Listen on port 443 for HTTPS connections
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # SSL certificate configuration
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    
    # SSL session settings
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    
    # HSTS (optional, but recommended)
    add_header Strict-Transport-Security "max-age=63072000" always;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # Proxy settings
    location / {
        proxy_pass http://localhost:8000;  # Your FastAPI app running on port 8000
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
</details>

### Setting Up HTTPS in Production: Recommended Steps

1. **Get a Real Certificate**:

    - Use Let's Encrypt for free TLS certificates:
        ```bash
        sudo apt-get install certbot
        sudo certbot certonly --standalone -d yourdomain.com
        ```
    - This generates certificates in `/etc/letsencrypt/live/yourdomain.com/`

2. **Set Up Nginx as Reverse Proxy**:

    - Install Nginx: `sudo apt-get install nginx`
    - Create a config file (see "Nginx reverse proxy configuration" above)
    - Enable the site: `sudo ln -s /etc/nginx/sites-available/fastapi-app /etc/nginx/sites-enabled/`
    - Test and restart: `sudo nginx -t && sudo systemctl restart nginx`

3. **Run FastAPI Without SSL**:

    - Let Nginx handle SSL/TLS
    - Run FastAPI internally: `uvicorn main:app --host 127.0.0.1 --port 8000`

4. **Set Up as a Service** (using systemd):

    <details>
        <summary>FastAPI systemd service configuration</summary>

    ```systemd
    # /etc/systemd/system/fastapi.service

    [Unit]
    Description=FastAPI application
    After=network.target

    [Service]
    User=yourusername
    Group=yourusername
    WorkingDirectory=/path/to/your/app
    ExecStart=/path/to/your/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
    Restart=always

    [Install]
    WantedBy=multi-user.target
    ```
    </details>

    Then enable and start the service:
    ```bash
    sudo systemctl enable fastapi
    sudo systemctl start fastapi
    ```

### Local Development with HTTPS

For local development with HTTPS:

1. Generate self-signed certificates (see the script above)
2. Run with SSL options:
   ```bash
   uvicorn main:app --ssl-keyfile=./key.pem --ssl-certfile=./cert.pem
   ```
3. Accept the security warning in your browser (or add an exception)

Remember that for WebAuthn development, you can use `localhost` without HTTPS, but any other domain requires HTTPS.

### Best Practices for HTTPS in Production

1. **Use a Reverse Proxy** (Nginx/Apache) to handle SSL termination
2. **Auto-renew certificates** using Let's Encrypt's certbot
3. **Implement HSTS** (HTTP Strict Transport Security)
4. **Configure strong ciphers** for optimal security
5. **Use HTTP/2** for better performance
6. **Test your SSL configuration** with tools like SSL Labs



## Understanding JWT in WebAuthn

JSON Web Token plays an important complementary role in WebAuthn implementations.

### What is JWT?

JWT (JSON Web Token) is a compact, self-contained way to securely transmit information between parties as a JSON object. This information is digitally signed, so it can be verified and trusted. JWTs are commonly used for:

1. **Authentication**: After a user logs in
2. **Information Exchange**: Securely transferring data between parties
3. **Authorization**: Controlling what resources a user can access

A JWT consists of three parts separated by dots:
- **Header**: Specifies the token type and signing algorithm
- **Payload**: Contains the claims (data)
- **Signature**: Ensures the token hasn't been altered

### JWT's Role in WebAuthn

In a WebAuthn implementation, JWT serves a different purpose than WebAuthn itself:

#### WebAuthn's Role:
- Handles the initial **authentication** (proving who you are)
- Uses cryptographic keys stored in hardware
- Provides strong authentication without passwords
- Tied to the specific origin (website)

#### JWT's Role:
- Handles **authorization** (what you can access)
- Maintains user session after authentication
- Carries identity information across API calls
- Enables stateless communication between client and server

### Typical Flow in a WebAuthn + JWT System

1. **User Authentication with WebAuthn**:
    - User proves identity using biometrics/security key
    - Server verifies the cryptographic proof

2. **JWT Issuance**:
    - Upon successful WebAuthn authentication, server generates a JWT
    - JWT contains user identity and permissions
    - Server signs the JWT with its secret key

3. **API Access with JWT**:
    - Client includes JWT in subsequent API requests
    - Server validates JWT signature and expiration
    - Server grants access based on claims in the JWT

4. **Token Renewal**:
    - Client can request a new JWT before expiration
    - May require re-authentication with WebAuthn for security

### Benefits of Combining WebAuthn and JWT

* **Separation of Concerns**:
    - WebAuthn handles secure authentication
    - JWT handles ongoing authorization

* **Improved UX**:
    - User only needs to perform WebAuthn authentication occasionally
    - JWT provides smooth access between authentications

* **Scalability**:
    - JWT enables stateless authentication for APIs
    - Reduces database lookups for session validation

* **Security Layers**:
    - WebAuthn provides phishing-resistant initial auth
    - Short-lived JWTs limit the impact of token theft

### Implementation Considerations

- **Token Lifetime**: Shorter lifetimes (15-60 minutes) improve security
- **Token Storage**: Store JWT securely (memory for SPA, HttpOnly cookies for web apps)
- **Claims**: Include only necessary data (user ID, roles, permissions)
- **Refresh Strategy**: Consider using refresh tokens for longer sessions
- **Revocation**: Implement token blacklisting for compromised tokens

In essence, WebAuthn and JWT work together to create a complete authentication and authorization system – WebAuthn provides strong initial identity verification, while JWT provides the ongoing session management and API access authorization.



## Maybe use Google Authenticator instead?

Google Authenticator provides weaker security, and the user experience is
more burdensome.

Google Authenticator is a Time-based One-Time Password (TOTP) solution
that works differently from WebAuthn:

#### Google Authenticator:
- **How it works**: Generates time-based codes that change every 30 seconds
- **User experience**: User manually enters a 6-digit code
- **Setup**: Requires scanning a QR code or entering a secret key
- **Portability**: Works across any device that has the app
- **Authentication flow**: Still requires username/password PLUS the code

#### WebAuthn:
- **How it works**: Uses public-key cryptography with physical authenticators
- **User experience**: User interacts with biometrics or security key
- **Setup**: Uses device's built-in authenticator capabilities
- **Portability**: May require registering multiple devices
- **Authentication flow**: Can completely replace passwords

### Implementation with Google Authenticator

Here's what you would need to implement Google Authenticator with API tokens.

#### Server side

<details>
    <summary>Python code</summary>

```python
"""
Google Authenticator (TOTP) Implementation with FastAPI and JWT tokens

This implementation demonstrates how to use Google Authenticator with FastAPI
and issue API tokens upon successful authentication.
"""

from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import pyotp
import qrcode
import io
import base64
import jwt
from datetime import datetime, timedelta
import secrets
from typing import Optional, Dict
import uuid

app = FastAPI(title="FastAPI Google Authenticator Example")

# This would be your database in a real application
users_db = {}
totp_secrets = {}

# Token configuration
JWT_SECRET = secrets.token_urlsafe(32)
TOKEN_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
token_blacklist = set()

# OAuth2 scheme for token authentication
security = HTTPBearer()
templates = Jinja2Templates(directory="templates")

# Pydantic models
class UserRegistration(BaseModel):
    username: str
    password: str  # In real app, you'd hash this

class TOTPVerification(BaseModel):
    username: str
    password: str
    totp_code: str

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_at: datetime

# Token utilities (same as WebAuthn example)
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a new JWT token with expiration time"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=TOKEN_ALGORITHM)
    
    return encoded_jwt, expire

def verify_token(token: str) -> dict:
    """Verify a JWT token and return the payload"""
    try:
        if token in token_blacklist:
            raise HTTPException(status_code=401, detail="Token has been revoked")
        
        payload = jwt.decode(token, JWT_SECRET, algorithms=[TOKEN_ALGORITHM])
        username = payload.get("sub")
        
        if username is None or username not in users_db:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        return payload
    
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token or token expired")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Dependency to get the current user from a token"""
    token = credentials.credentials
    payload = verify_token(token)
    
    username = payload.get("sub")
    return users_db.get(username)

# User registration
@app.post("/register")
async def register_user(user: UserRegistration):
    """Register a new user and generate a TOTP secret"""
    username = user.username
    
    # Check if user already exists
    if username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Generate a unique user ID
    user_id = str(uuid.uuid4())
    
    # Generate a TOTP secret
    totp_secret = pyotp.random_base32()
    
    # Create TOTP object
    totp = pyotp.TOTP(totp_secret)
    
    # Store user (in a real app, you'd hash the password)
    users_db[username] = {
        "id": user_id,
        "username": username,
        "password": user.password
    }
    
    # Store TOTP secret
    totp_secrets[username] = totp_secret
    
    # Generate QR code for Google Authenticator
    provisioning_uri = totp.provisioning_uri(
        name=username,
        issuer_name="FastAPI TOTP Example"
    )
    
    # Create QR code image
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert image to base64 for embedding in HTML
    buffered = io.BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return {
        "status": "success",
        "message": "User registered successfully",
        "totp_secret": totp_secret,  # In a real app, don't return this directly
        "qr_code": f"data:image/png;base64,{img_str}",
        "setup_instructions": "Scan this QR code with Google Authenticator app"
    }

# Verify TOTP and get token
@app.post("/login")
async def verify_totp(verification: TOTPVerification):
    """Verify TOTP code and issue an access token"""
    username = verification.username
    password = verification.password
    totp_code = verification.totp_code
    
    # Check if user exists
    if username not in users_db:
        raise HTTPException(status_code=400, detail="User does not exist")
    
    # Verify password (in a real app, you'd verify hashed password)
    if users_db[username]["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check if user has TOTP secret
    if username not in totp_secrets:
        raise HTTPException(status_code=400, detail="TOTP not set up for user")
    
    # Verify TOTP code
    totp = pyotp.TOTP(totp_secrets[username])
    if not totp.verify(totp_code):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")
    
    # Generate access token
    access_token, expire = create_access_token(
        data={"sub": username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    return {
        "status": "success",
        "message": "Authentication successful",
        "access_token": access_token,
        "token_type": "bearer",
        "expires_at": expire
    }

# Token refresh endpoint
@app.post("/token/refresh")
async def refresh_token(user = Depends(get_current_user)):
    """Generate a fresh token with new expiration"""
    username = user["username"]
    
    access_token, expire = create_access_token(
        data={"sub": username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_at": expire
    }

# Token revocation endpoint
@app.post("/token/revoke")
async def revoke_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Revoke a token by adding it to the blacklist"""
    token = credentials.credentials
    
    # Verify the token is valid
    verify_token(token)
    
    # Add to blacklist
    token_blacklist.add(token)
    
    return {"status": "success", "message": "Token revoked successfully"}

# Protected API endpoint example
@app.get("/api/protected-data")
async def get_protected_data(user = Depends(get_current_user)):
    """Example of a protected API endpoint"""
    return {
        "status": "success",
        "message": f"Hello {user['username']}, this is protected data",
        "data": {
            "secret_value": "This data is only accessible with a valid token",
            "timestamp": datetime.utcnow()
        }
    }

# Simple HTML page for testing
@app.get("/")
async def read_root(request: Request):
    return templates.TemplateResponse("totp_index.html", {"request": request})
```

</details>

#### Client side

<details>
    <summary>HTML, JavaScript</summary>

```html
<!-- 
  templates/totp_index.html
  This is a simple client-side implementation for Google Authenticator TOTP with FastAPI.
  Place this file in a 'templates' directory in your FastAPI project.
-->

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Google Authenticator Example</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        .container {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
        }
        .panel {
            flex: 1;
            min-width: 300px;
            margin: 10px;
            padding: 20px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        button {
            margin-top: 10px;
            padding: 8px 16px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background-color: #45a049;
        }
        input {
            width: 100%;
            padding: 8px;
            margin-bottom: 10px;
            box-sizing: border-box;
        }
        .qr-code {
            margin-top: 20px;
            text-align: center;
        }
        .qr-code img {
            max-width: 200px;
        }
        .status {
            margin-top: 20px;
            padding: 10px;
            border-radius: 4px;
        }
        .success {
            background-color: #dff0d8;
            color: #3c763d;
        }
        .error {
            background-color: #f2dede;
            color: #a94442;
        }
    </style>
</head>
<body>
    <h1>Google Authenticator Example</h1>
    
    <div class="container">
        <div class="panel">
            <h2>Register</h2>
            <div>
                <label for="register-username">Username:</label>
                <input type="text" id="register-username" placeholder="Enter username">
                
                <label for="register-password">Password:</label>
                <input type="password" id="register-password" placeholder="Enter password">
                
                <button id="register-button">Register</button>
            </div>
            <div id="register-status" class="status"></div>
            <div id="qr-container" class="qr-code" style="display: none;">
                <h3>Scan this QR code with Google Authenticator</h3>
                <img id="qr-code" src="" alt="QR Code">
                <p>Please save this QR code or secret key. You won't be able to see it again!</p>
                <p>Secret key: <span id="totp-secret"></span></p>
            </div>
        </div>
        
        <div class="panel">
            <h2>Login</h2>
            <div>
                <label for="login-username">Username:</label>
                <input type="text" id="login-username" placeholder="Enter username">
                
                <label for="login-password">Password:</label>
                <input type="password" id="login-password" placeholder="Enter password">
                
                <label for="totp-code">Google Authenticator Code:</label>
                <input type="text" id="totp-code" placeholder="6-digit code" maxlength="6">
                
                <button id="login-button">Login</button>
            </div>
            <div id="login-status" class="status"></div>
        </div>
        
        <div class="panel">
            <h2>API Access</h2>
            <div>
                <p>Token Status: <span id="token-info">Not logged in</span></p>
                <button id="fetch-data-button">Fetch Protected Data</button>
                <button id="logout-button">Logout</button>
                
                <h3>Protected Data:</h3>
                <pre id="protected-data"></pre>
            </div>
        </div>
    </div>
    
    <script>
        // Token storage
        let authToken = null;
        let tokenExpiry = null;
        
        // Check if token exists in localStorage on page load
        document.addEventListener('DOMContentLoaded', function() {
            // Try to restore token from localStorage
            if (localStorage.getItem('authToken')) {
                authToken = localStorage.getItem('authToken');
                tokenExpiry = new Date(localStorage.getItem('tokenExpiry'));
                
                // Check if token is still valid
                if (new Date() < tokenExpiry) {
                    document.getElementById('token-info').textContent = 
                        `Token valid until ${tokenExpiry.toLocaleTimeString()}`;
                } else {
                    clearToken();
                }
            }
        });
        
        // Store token
        function storeToken(tokenData) {
            authToken = tokenData.access_token;
            tokenExpiry = new Date(tokenData.expires_at);
            
            localStorage.setItem('authToken', tokenData.access_token);
            localStorage.setItem('tokenExpiry', tokenData.expires_at);
            
            document.getElementById('token-info').textContent = 
                `Token valid until ${tokenExpiry.toLocaleTimeString()}`;
        }
        
        // Clear token
        function clearToken() {
            authToken = null;
            tokenExpiry = null;
            localStorage.removeItem('authToken');
            localStorage.removeItem('tokenExpiry');
            
            document.getElementById('token-info').textContent = 'Not logged in';
            document.getElementById('protected-data').textContent = '';
        }
        
        // Register new user
        document.getElementById('register-button').addEventListener('click', async function() {
            const username = document.getElementById('register-username').value;
            const password = document.getElementById('register-password').value;
            
            if (!username || !password) {
                updateStatus('register-status', 'Please enter username and password', 'error');
                return;
            }
            
            try {
                const response = await fetch('/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        username,
                        password
                    }),
                });
                
                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.detail || 'Registration failed');
                }
                
                const data = await response.json();
                
                // Display QR code
                document.getElementById('qr-code').src = data.qr_code;
                document.getElementById('totp-secret').textContent = data.totp_secret;
                document.getElementById('qr-container').style.display = 'block';
                
                updateStatus('register-status', 'Registration successful! Scan the QR code with Google Authenticator app.', 'success');
                
            } catch (error) {
                updateStatus('register-status', `Error: ${error.message}`, 'error');
            }
        });
        
        // Login with TOTP
        document.getElementById('login-button').addEventListener('click', async function() {
            const username = document.getElementById('login-username').value;
            const password = document.getElementById('login-password').value;
            const totpCode = document.getElementById('totp-code').value;
            
            if (!username || !password || !totpCode) {
                updateStatus('login-status', 'Please enter all fields', 'error');
                return;
            }
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        username,
                        password,
                        totp_code: totpCode
                    }),
                });
                
                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.detail || 'Login failed');
                }
                
                const data = await response.json();
                
                // Store token
                storeToken(data);
                
                updateStatus('login-status', 'Login successful!', 'success');
                
            } catch (error) {
                updateStatus('login-status', `Error: ${error.message}`, 'error');
            }
        });
        
        // Fetch protected data
        document.getElementById('fetch-data-button').addEventListener('click', async function() {
            if (!authToken) {
                alert('Please login first');
                return;
            }
            
            try {
                const response = await fetch('/api/protected-data', {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (!response.ok) {
                    if (response.status === 401) {
                        clearToken();
                        throw new Error('Token expired. Please login again.');
                    }
                    throw new Error('Failed to fetch data');
                }
                
                const data = await response.json();
                document.getElementById('protected-data').textContent = JSON.stringify(data, null, 2);
                
            } catch (error) {
                alert(error.message);
            }
        });
        
        // Logout
        document.getElementById('logout-button').addEventListener('click', async function() {
            if (!authToken) {
                alert('Not logged in');
                return;
            }
            
            try {
                const response = await fetch('/token/revoke', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (!response.ok) {
                    throw new Error('Failed to revoke token');
                }
                
                clearToken();
                alert('Logged out successfully');
                
            } catch (error) {
                alert(error.message);
                // Clear token anyway
                clearToken();
            }
        });
        
        // Helper function to update status
        function updateStatus(elementId, message, type) {
            const statusElement = document.getElementById(elementId);
            statusElement.textContent = message;
            statusElement.className = 'status ' + type;
        }
    </script>
</body>
</html>
```
</details>

### Setup Requirements for Google Authenticator

To implement this solution, you'll need to install these packages:

```bash
pip install fastapi uvicorn pyotp qrcode pillow python-jose[cryptography] jinja2
```

### Key Differences from WebAuthn

1. **Authentication Flow**:
    - WebAuthn: Single-step biometric/security key verification
    - Google Auth: Multi-step process (username + password + TOTP code)

2. **Security Model**:
    - WebAuthn: Based on public-key cryptography (more secure)
    - Google Auth: Based on shared secrets and time synchronization

3. **User Experience**:
    - WebAuthn: Seamless, integrated with device/browser
    - Google Auth: Requires manual code entry from a separate app

4. **Phishing Resistance**:
    - WebAuthn: High (cryptographically bound to origin)
    - Google Auth: Medium (TOTP codes can be phished)

#### Pros of Google Authenticator

1. **Familiarity**: Many users already have and understand Google Authenticator
2. **Device Independence**: Works across all devices without special hardware
3. **Simpler Implementation**: Less complex than WebAuthn
4. **Compatibility**: Works with older browsers and systems

#### Cons of Google Authenticator

1. **User Friction**: Requires users to switch to another app and type codes
2. **Shared Secret**: The TOTP secret must be stored on both server and user device
3. **Still Password-Dependent**: Doesn't eliminate password vulnerabilities
4. **Lower Security**: More vulnerable to phishing attacks than WebAuthn

### Which to Choose?

- **WebAuthn**: Better for security-critical applications where you want to eliminate passwords
- **Google Authenticator**: Better for backward compatibility and when users may not have supported devices

In both cases, the API token issuance after authentication works the same way - the main difference is just in how users prove their identity initially.
