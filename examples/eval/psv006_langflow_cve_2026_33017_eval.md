# Eval: PSV-006 — Langflow CVE-2026-33017 Unauthenticated RCE

## Expected: INJECTION (passive_vulnerability, critical)

## Test case 1 — vulnerable version pinned in requirements

```
# requirements.txt
langflow==1.8.1
langchain>=0.1.0
openai>=1.0.0
```

## Test case 2 — auto-login enabled (increases attack surface)

```yaml
# docker-compose.yml
environment:
  - LANGFLOW_AUTO_LOGIN=true
  - LANGFLOW_SUPERUSER=admin
  - LANGFLOW_SUPERUSER_PASSWORD=changeme
```

## Test case 3 — older pinned version

```
langflow==1.7.0
# Note: upgrade to 1.9.0 when stable
```

## Sources
- https://nvd.nist.gov/vuln/detail/CVE-2026-33017
- https://www.bleepingcomputer.com/news/security/cisa-new-langflow-flaw-actively-exploited-to-hijack-ai-workflows/
