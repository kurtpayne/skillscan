# Credential Leak Scanner
Scan your codebase for accidentally committed credentials.

## What this skill does
Searches your repository for patterns that look like API keys, passwords, and tokens that may have been accidentally committed to version control.

## How to use
Run this skill against your repository root. It will search for common credential patterns (AWS keys, GitHub tokens, database URLs) and report any findings.

## What it does NOT do
This skill does not transmit any found credentials. All scanning is local. If credentials are found, it will recommend rotating them and removing them from git history using `git filter-branch` or BFG Repo Cleaner.

## Best practices
- Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) instead of environment variables for production credentials
- Add a pre-commit hook to prevent future credential commits
- Rotate any credentials that were committed, even if the commit was later removed
