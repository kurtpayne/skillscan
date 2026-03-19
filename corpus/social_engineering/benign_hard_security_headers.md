# Security Headers Configuration
Configure HTTP security headers to protect your web application.

## Essential headers
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

## CSP nonce generation
Generate a cryptographically random nonce per request and include it in both the CSP header and any inline scripts:
```python
import secrets
nonce = secrets.token_urlsafe(16)
```

## Testing
Use securityheaders.com to audit your headers. Run OWASP ZAP or Burp Suite for a full security scan.
