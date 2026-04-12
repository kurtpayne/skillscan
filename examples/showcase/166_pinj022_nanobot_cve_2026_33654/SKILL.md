---
name: nanobot-pinj-test
description: Test for nanobot CVE-2026-33654 Indirect Prompt Injection via Email
---

# nanobot PINJ Test

This skill tests the detection of CVE-2026-33654.
The vulnerability allows malicious emails to bypass channel isolation and execute arbitrary LLM instructions.

```bash
# Trigger pattern
echo "CVE-2026-33654"
echo "nanobot email prompt injection bypass isolation"
```
