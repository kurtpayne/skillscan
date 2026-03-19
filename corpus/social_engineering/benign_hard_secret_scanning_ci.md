# Secret Scanning in CI/CD
Prevent secrets from being committed to version control.

## Pre-commit hooks
Install detect-secrets or gitleaks as a pre-commit hook to block commits containing secrets:
```bash
pip install detect-secrets
detect-secrets scan > .secrets.baseline
# Add to .pre-commit-config.yaml:
# - repo: https://github.com/Yelp/detect-secrets
#   hooks:
#     - id: detect-secrets
#       args: ['--baseline', '.secrets.baseline']
```

## CI/CD scanning
Run secret scanning in CI to catch anything that slipped through:
```yaml
- name: Scan for secrets
  uses: gitleaks/gitleaks-action@v2
```

## GitHub secret scanning
Enable GitHub's built-in secret scanning (Settings → Security → Secret scanning). It automatically detects and alerts on common secret patterns (AWS keys, GitHub tokens, Stripe keys) pushed to your repository.

## If a secret is committed
1. Rotate the secret immediately — assume it's compromised
2. Remove it from git history using `git filter-repo` (not `git rm` — the secret remains in history)
3. Force-push the cleaned history
4. Notify affected service providers if the secret was for a third-party service
