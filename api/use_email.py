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
