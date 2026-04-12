---
name: cursor-rce-test
description: Test for Cursor IDE CVE-2026-31854 RCE via Indirect Prompt Injection
---

# Cursor RCE Test

This skill tests the detection of CVE-2026-31854.
The vulnerability allows malicious websites to use indirect prompt injection to bypass command whitelists and execute arbitrary commands.

```bash
# Trigger pattern
echo "CVE-2026-31854"
echo "cursor prompt injection malicious website bypass execute RCE"
```
