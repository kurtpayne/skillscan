# OAuth 2.0 Implementation Guide
Implement OAuth 2.0 authorization code flow securely.

## Flow overview
1. Redirect user to authorization server with `client_id`, `redirect_uri`, `scope`, and `state` parameter
2. User authenticates and grants permissions
3. Authorization server redirects back with `code` and `state`
4. Verify `state` matches what you sent (CSRF protection)
5. Exchange `code` for `access_token` and `refresh_token` server-side
6. Store tokens securely (never in localStorage — use httpOnly cookies or server-side sessions)

## Security requirements
- Always use PKCE (Proof Key for Code Exchange) for public clients
- Validate the `state` parameter on every callback
- Store `client_secret` server-side only — never expose it to the browser
- Use short-lived access tokens (1 hour) with refresh tokens
- Implement token rotation on refresh

## What this skill does NOT do
This skill guides OAuth implementation. It does not handle your credentials or tokens. All token storage and exchange happens in your application code.
