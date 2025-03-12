# User authentication, how to do it?

# Prompt

Let's look at user authentication on websites written in Python with FastAPI served by uvicorn. I'd like to use MFA (probably email the user an OTP) to set up a passkey, and use the passkey for authentication after that.

# Implementing MFA and Passkeys in FastAPI

FastAPI offers robust options for implementing secure authentication systems, including multi-factor authentication (MFA) with passkeys. Here's how to create a system that uses email OTP for initial verification and passkeys for subsequent authentication.

### Setting Up the Basic FastAPI Application

First, let's set up a basic FastAPI application with the necessary dependencies:

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import uvicorn

app = FastAPI()

# For serving the application
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, ssl_keyfile="path/to/key.pem", 
                ssl_certfile="path/to/cert.pem")
```

Always use HTTPS for secure communication by providing SSL certificate and key files [A1].

### Implementing Email-Based OTP Authentication

To implement OTP via email, you'll need:

1. A user model
2. OTP generation functionality 
3. Email sending capabilities

```python
import pyotp
from pydantic import BaseModel, EmailStr
from datetime import datetime
from email.message import EmailMessage
import smtplib

class User(BaseModel):
    username: str
    email: EmailStr
    hashed_password: str
    otp_enabled: bool = False
    otp_verified: bool = False
    otp_base32: str = None
    passkey_registered: bool = False

def generate_otp_secret():
    """Generate a base32 encoded secret for OTP."""
    return pyotp.random_base32()

def verify_otp(otp_secret, token):
    """Verify an OTP token against the secret."""
    totp = pyotp.TOTP(otp_secret)
    return totp.verify(token)

def send_otp_email(email, otp):
    """Send OTP token via email."""
    msg = EmailMessage()
    msg.set_content(f"Your OTP code is: {otp}")
    msg['Subject'] = "Your Authentication Code"
    msg['From'] = "noreply@yourapp.com"
    msg['To'] = email
    
    # Configure your SMTP server details
    server = smtplib.SMTP('smtp.yourserver.com', 587)
    server.starttls()
    server.login("your_email@example.com", "your_password")
    server.send_message(msg)
    server.quit()
```

### User Registration and OTP Verification Endpoints

Now, let's create endpoints for user registration and OTP verification:

```python
@app.post("/api/auth/register")
async def register_user(user_data: UserCreate):
    # Hash the password, create user in DB
    # Generate OTP secret
    otp_secret = generate_otp_secret()
    
    # Store user with OTP secret in database
    # ...
    
    # Generate current OTP
    totp = pyotp.TOTP(otp_secret)
    current_otp = totp.now()
    
    # Send OTP via email
    send_otp_email(user_data.email, current_otp)
    
    return {"message": "User registered. OTP sent to email for verification."}

@app.post("/api/auth/verify-otp")
async def verify_otp_code(payload: OTPVerification):
    # Get user from database
    # user = get_user_by_id(payload.user_id)
    
    # Verify OTP
    totp = pyotp.TOTP(user.otp_base32)
    if not totp.verify(payload.token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP token"
        )
    
    # Update user as verified
    # update_user_verification(user.id, otp_verified=True)
    
    return {"verified": True}
```

### Integrating Passkey Authentication

After OTP verification, you can set up passkey registration. For passkey integration, you have two main options:

#### Option 1: Use Corbado for Passkey Integration

Corbado provides a complete solution for passkey integration with FastAPI [A7] [A8] [A10]:

```python
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # Serve a page with Corbado's web component for passkey registration
    return templates.TemplateResponse("index.html", {"request": request, "project_id": "YOUR_CORBADO_PROJECT_ID"})

@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request):
    # Verify Corbado session and extract user data
    # This requires the Corbado Python SDK
    session_token = request.cookies.get("corbado_session_token")
    # Verify and extract user data from session
    return templates.TemplateResponse("profile.html", {"request": request, "user": user_data})
```

In your HTML template, include Corbado's web components:

```html
<script type="module" src="https://cdn.jsdelivr.net/npm/@corbado/web-js@latest/dist/index.js"></script>
<corbado-auth project-id="YOUR_PROJECT_ID"></corbado-auth>
```

#### Option 2: Custom Implementation with PyOTP and WebAuthn

For a more customized solution, you can integrate WebAuthn for passkey support:

```python
@app.post("/api/auth/passkey/register")
async def register_passkey(user_id: str):
    # Generate WebAuthn registration options
    # Return challenge to client
    pass

@app.post("/api/auth/passkey/verify")
async def verify_passkey_registration(credential_data: dict):
    # Verify registration response
    # Store credential for future authentication
    pass

@app.post("/api/auth/passkey/authenticate")
async def authenticate_with_passkey(credential_response: dict):
    # Verify authentication response
    # Issue session token or JWT
    pass
```

### Complete Authentication Flow

The complete flow would be:

1. User registers with email and password
2. System generates OTP and sends via email
3. User verifies OTP to complete initial authentication
4. User registers a passkey (using browser's WebAuthn API)
5. For subsequent logins, user authenticates with the passkey directly

### Securing Your FastAPI Application

Always follow these security best practices [A1]:

1. Use HTTPS for all communications
2. Implement proper JWT token validation
3. Store user credentials securely (use password hashing)
4. Set appropriate token expiration times
5. Implement rate limiting to prevent brute force attacks

By combining email-based OTP for initial verification and passkeys for subsequent authentication, you create a secure and user-friendly authentication system that leverages the strengths of both methods [A4] [A7].

[A1]: https://escape.tech/blog/how-to-secure-fastapi-api/
[A2]: https://fastapi.tiangolo.com/advanced/security/http-basic-auth/
[A3]: https://fastapi.tiangolo.com/tutorial/security/simple-oauth2/
[A4]: https://codevoweb.com/two-factor-authentication-2fa-in-fastapi-and-python/
[A5]: https://github.com/dfm88/fastapi-two-factor-authentication
[A6]: https://github.com/pasan1/Simple-FastAPI-User-Authentication
[A7]: https://www.corbado.com/passkeys/fastapi
[A8]: https://dev.to/corbado/how-to-integrate-passkeys-in-python-fastapi-4oo6
[A9]: https://fastapi.tiangolo.com/tutorial/security/first-steps/
[A10]: https://www.corbado.com/blog/passkeys-fastapi
[A11]: https://www.youtube.com/watch?v=0A_GCXBCNUQ
[A12]: https://community.auth0.com/t/fastapi-authentication-by-example/157699
[A13]: https://github.com/sabuhibrahim/fastapi-jwt-auth-full-example
[A14]: https://fastapi.tiangolo.com/tutorial/security/
[A15]: https://stackoverflow.com/questions/77001129/how-to-configure-fastapi-logging-so-that-it-works-both-with-uvicorn-locally-and
[A16]: https://www.reddit.com/r/FastAPI/comments/1h53yd7/getting_2fa_to_work_with_the_swagger_ui/
[A17]: https://blog.ishangavidusha.com/create-otpmobile-verification-api-with-python-fastapi-and-sendlk-sms-gateway
[A18]: https://stackoverflow.com/questions/68362154/fastapi-user-authentication-with-verification-email
[A19]: https://towardsdev.com/elevating-security-implementing-two-factor-authentication-in-fastapi-with-a-simple-example-a711a3cb8c3
[A20]: https://github.com/wpcodevo/2fa_fastapi
[A21]: https://github.com/vinodiOS/two-factor-auth-FastAPI
[A22]: https://www.youtube.com/watch?v=TLjU4fs7ARU
[A23]: https://pyauth.github.io/pyotp/
[A24]: https://www.youtube.com/watch?v=NJu0tmwb3n0
[A25]: https://github.com/sussy123hahaha/passkeys-svelte-fastapi
[A26]: https://developer.auth0.com/resources/guides/web-app/fastapi/basic-authentication
[A27]: https://github.com/corbado/example-passkeys-fastapi
[A28]: https://passkeys.substack.com/p/fastapi-passkeys-9-webauthn-server
[A29]: https://github.com/corbado/passkeys-svelte-fastapi
[A30]: https://blog.stackademic.com/authentication-and-authorization-with-fastapi-8fcab4fb09d8
[A31]: https://github.com/amisadmin/fastapi-user-auth
[A32]: https://stackoverflow.com/questions/78245491/mtls-not-working-with-fastapi-and-uvicorn
[A33]: https://testdriven.io/blog/fastapi-jwt-auth/
[A34]: https://github.com/Icebreaker454/otp-auth-example
[A35]: https://app-generator.dev/docs/technologies/fastapi/multi-factor-authentication.html
[A36]: https://www.twilio.com/en-us/blog/email-address-verification-fastapi-twilio-verify
[A37]: https://dev.to/krjakbrjak/fastapi-and-two-factor-authentication-291a
[A38]: https://timberry.dev/fastapi-with-apikeys

# Prompt

```python
uvicorn.run("main:app", host="0.0.0.0", port=8000,
            ssl_keyfile="path/to/key.pem",
            ssl_certfile="path/to/cert.pem")
```

How can I generate key.pem and cert.pem? Maybe use letsencrypt?

# Certificates and all that

To generate SSL certificate files for your uvicorn server, you have two main options: using Let's Encrypt for production environments or creating self-signed certificates for development.

## Using Let's Encrypt (for production)

Let's Encrypt provides free, trusted SSL certificates valid for 90 days with automatic renewal. This is the recommended approach for production environments:

1. **Install Certbot** (Let's Encrypt's client):
   ```bash
   sudo apt-get update
   sudo apt-get install certbot
   ```

2. **Obtain certificates** using the standalone method (temporarily stops your web server):
   ```bash
   sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com
   ```

3. **Copy certificates** to your application directory:
   ```bash
   sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem path/to/key.pem
   sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem path/to/cert.pem
   ```

Let's Encrypt certificates are stored in `/etc/letsencrypt/live/yourdomain.com/` with the private key at `privkey.pem` and the certificate at `fullchain.pem` [B2]. The certificates expire after 90 days, but Certbot sets up automatic renewal tasks.

## Creating Self-Signed Certificates (for development)

For local development or testing, you can create self-signed certificates using OpenSSL:

1. **Generate the private key**:
   ```bash
   openssl genrsa -out key.pem 2048
   ```

2. **Create a certificate signing request (CSR)**:
   ```bash
   openssl req -new -key key.pem -out csr.pem
   ```
   You'll need to provide information like country, state, etc.

3. **Generate the certificate using the private key and CSR**:
   ```bash
   openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out cert.pem
   ```

This creates a self-signed certificate valid for 365 days [B4] [B7]. Note that browsers will show a security warning with self-signed certificates since they're not issued by a trusted certificate authority.

## Using the Certificates with uvicorn

Once you have your certificate files, update your uvicorn run command with the correct paths:

```python
uvicorn.run("main:app", host="0.0.0.0", port=8000, 
            ssl_keyfile="path/to/key.pem", 
            ssl_certfile="path/to/cert.pem")
```

Remember that for production environments, Let's Encrypt is preferred as it provides trusted certificates. Self-signed certificates should be used only for development or internal applications.

[B1]: https://www.linode.com/docs/guides/install-lets-encrypt-to-create-ssl-certificates/
[B2]: https://www.digitalocean.com/community/tutorials/how-to-secure-apache-with-let-s-encrypt-on-ubuntu
[B3]: https://www.sslforfree.com
[B4]: https://gist.github.com/taoyuan/39d9bc24bafc8cc45663683eae36eb1a
[B5]: https://punchsalad.com/ssl-certificate-generator/
[B6]: https://letsencrypt.org/getting-started/
[B7]: https://devcenter.heroku.com/articles/ssl-certificate-self
[B8]: https://community.letsencrypt.org/t/how-to-get-ssl-certificate-from-letsencrypt-org/30095
[B9]: https://www.reddit.com/r/webdev/comments/1chxc0f/is_lets_encrypt_good_enough/
[B10]: https://stackoverflow.com/questions/67775219/how-do-i-setup-https-with-a-letsencrypt-certificate
[B11]: https://www.youtube.com/watch?v=7haN-Aghlso
[B12]: https://letsencrypt.org/how-it-works/
[B13]: https://community.letsencrypt.org/t/how-do-i-generate-the-lets-encrypt-certificate-and-key-on-my-own-device-more-info-inside/27510
[B14]: https://www.youtube.com/watch?v=8huMBHx-TKY
[B15]: https://letsencrypt.org
[B16]: https://letsencrypt.org/docs/integration-guide/
[B17]: https://community.letsencrypt.org/t/i-need-help-creating-ssl-certificate-please/219817
[B18]: https://community.letsencrypt.org/t/how-can-i-create-a-certificate-for-a-server-that-will-never-be-connected-to-the-internet/196108
[B19]: https://www.sectigo.com/resource-library/what-is-a-self-signed-certificate
[B20]: https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/
[B21]: https://devopscube.com/create-self-signed-certificates-openssl/
[B22]: https://www.reddit.com/r/selfhosted/comments/wwitve/ssl_certificates_alternatives_for_lan_only_server/
[B23]: https://community.letsencrypt.org/t/possible-to-install-certificate-without-certbot-or-ssh-acces/191343
[B24]: https://stackoverflow.com/questions/10175812/how-can-i-generate-a-self-signed-ssl-certificate-using-openssl
[B25]: https://kb.teramind.co/en/articles/8791235-how-to-generate-your-own-self-signed-ssl-certificates-for-use-with-an-on-premise-deployments
[B26]: https://community.letsencrypt.org/t/how-am-i-supposed-for-gods-sake-to-get-lets-encrypts-certificates-using-windows-without-setting-up-a-web-server/131691
[B27]: https://regery.com/en/security/ssl-tools/self-signed-certificate-generator
[B28]: https://stackoverflow.com/questions/32052543/what-is-the-alternative-option-of-self-signed-certificates-in-production-for-int
[B29]: https://serverfault.com/questions/926974/is-there-a-reason-to-use-an-ssl-certificate-other-than-lets-encrypts-free-ssl
[B30]: https://www.youtube.com/watch?v=jrR_WfgmWEw
[B31]: https://stackoverflow.com/questions/50389883/generate-crt-key-ssl-files-from-lets-encrypt-from-scratch
[B32]: https://doc.owncloud.com/server/next/admin_manual/installation/letsencrypt/using_letsencrypt.html
[B33]: https://www.digitalocean.com/community/tutorials/an-introduction-to-let-s-encrypt
[B34]: https://community.letsencrypt.org/t/create-certificates-manually-without-acme-client-software/128918
[B35]: https://security.stackexchange.com/questions/241983/requesting-an-ssl-certificate-without-a-csr-can-it-be-done
[B36]: https://www.reddit.com/r/homelab/comments/z43334/how_to_create_ssl_certs_for_local_domain/
[B37]: https://unix.stackexchange.com/questions/104171/create-ssl-certificate-non-interactively
