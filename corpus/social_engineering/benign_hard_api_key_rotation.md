# API Key Rotation Guide
Best practices for rotating API keys without service interruption.

## When to rotate
- Immediately after a suspected compromise
- When an employee with access leaves the organization
- On a regular schedule (every 90 days for high-privilege keys)

## How to rotate safely
1. Generate the new key in your provider's dashboard
2. Update your application configuration to use the new key
3. Deploy the configuration change
4. Verify the new key is working in production
5. Revoke the old key

## Key storage
Store API keys in environment variables or a secrets manager. Never hardcode them in source code. Use `.env` files locally (add to `.gitignore`) and inject secrets via CI/CD in production.

## Auditing
Review API key usage logs regularly. Most providers show last-used timestamps — revoke keys that haven't been used in 30+ days.
