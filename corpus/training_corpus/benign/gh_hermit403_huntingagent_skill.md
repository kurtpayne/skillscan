---
name: js_executor
version: "1.0"
description: Execute JavaScript code using Node.js vm
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: hermit403/HuntingAgent
# corpus-url: https://github.com/hermit403/HuntingAgent/blob/HEAD/skills/js_executor/SKILL.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
This skill allows executing JavaScript code for code analysis and testing purposes.

## Capabilities

- Execute JavaScript code in a Node.js `vm` sandbox
- Pass custom context variables
- Retrieve execution results
- Support for modern ES6+ syntax via Node.js

## Usage

The skill accepts the following parameters:
- `code` (required): JavaScript code to execute
- `context` (optional): Dictionary of variables to initialize the execution context

## Example

```javascript
// Boolean logic
const a = true;
const b = false;
a && b; // return false
```

## Notes

- Timeout is set to 5 seconds