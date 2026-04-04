---
name: telnyx-version-showcase
description: Showcase for SUP-027 Compromised Telnyx package version reference
---

# Telnyx Compromised Version Showcase

This showcase demonstrates the detection of a compromised version of the telnyx package.

```bash
# Installing a known malicious version of telnyx
pip install telnyx==4.87.1
```

```python
# Or in a requirements file
requirements = {
    "telnyx": "4.87.2"
}
```
