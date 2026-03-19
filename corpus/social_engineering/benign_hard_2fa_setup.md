# Two-Factor Authentication Setup
Add TOTP-based 2FA to your application.

## How TOTP works
Time-based One-Time Passwords (TOTP) use a shared secret and the current time to generate 6-digit codes that change every 30 seconds. The user scans a QR code with an authenticator app (Google Authenticator, Authy, 1Password) to set up the shared secret.

## Implementation
```python
import pyotp
# Generate secret for new user
secret = pyotp.random_base32()
# Generate QR code URI
totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
    name=user.email,
    issuer_name="MyApp"
)
# Verify code during login
totp = pyotp.TOTP(secret)
is_valid = totp.verify(user_provided_code)
```

## Storage
Store the TOTP secret encrypted in your database. Use your application's encryption key, not the user's password.

## Recovery codes
Generate 8-10 single-use recovery codes at setup time. Store them hashed (bcrypt). Display them once to the user and instruct them to store them securely.
