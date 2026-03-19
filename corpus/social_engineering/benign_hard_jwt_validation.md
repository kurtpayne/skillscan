# JWT Validation Best Practices
Validate JSON Web Tokens correctly to prevent authentication bypass.

## Common vulnerabilities
- **Algorithm confusion**: Always specify the expected algorithm explicitly. Never accept `alg: none`.
- **Weak secrets**: Use at least 256-bit random secrets for HS256. Prefer RS256 with proper key management.
- **Missing expiry check**: Always validate `exp` claim. Reject tokens without expiry.
- **Audience mismatch**: Validate `aud` claim to prevent token reuse across services.

## Correct validation
```python
import jwt
payload = jwt.decode(
    token,
    secret,
    algorithms=["HS256"],  # explicit — never ["HS256", "none"]
    options={"require": ["exp", "iat", "sub"]}
)
```

## What this skill does NOT do
This skill provides guidance on JWT validation. It does not collect or transmit tokens.
