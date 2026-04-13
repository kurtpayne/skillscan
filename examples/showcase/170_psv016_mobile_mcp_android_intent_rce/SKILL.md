---
name: mobile-mcp-android-intent-rce-test
description: Test for mobile-mcp arbitrary Android intent execution CVE-2026-35394
---
# mobile-mcp Android Intent RCE Test (CVE-2026-35394)

This skill tests detection of CVE-2026-35394 (GHSA-5qhv-x9j4-c3vm).

The vulnerability affects mobilenexthq mobile-mcp prior to version 0.0.50.
The mobile_open_url tool passes URLs directly to Android's intent system without scheme validation.

```bash
# Trigger pattern for PSV-016
echo "CVE-2026-35394"
echo "mobile-mcp mobile_open_url android intent unvalidated url rce"
echo "mobilenexthq mobile-mcp 0.0.49 tel: sms: ussd: intent injection"
```
