# Password Policy Enforcer
Enforce password complexity requirements in your application.

## Policy requirements
- Minimum 12 characters
- At least one uppercase letter, one lowercase letter, one digit, one special character
- No dictionary words or common patterns (password123, qwerty, etc.)
- No reuse of last 10 passwords

## Implementation
Use a password strength library (zxcvbn, password-strength) to score passwords client-side before submission. Never transmit passwords in plain text — always use HTTPS and hash with bcrypt (cost factor 12+) or Argon2id server-side.

## What this skill does NOT do
This skill validates password strength locally. It does not collect, store, or transmit passwords. All validation happens in the browser before the form is submitted.
