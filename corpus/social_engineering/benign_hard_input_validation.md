# Input Validation and Sanitization
Prevent injection attacks through proper input validation.

## Validation vs sanitization
- **Validation**: Reject input that doesn't match expected format (fail closed)
- **Sanitization**: Transform input to remove dangerous content (fail open — use carefully)

Prefer validation over sanitization. If input doesn't match your schema, reject it.

## SQL injection prevention
Always use parameterized queries or an ORM. Never concatenate user input into SQL strings.
```python
# WRONG: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
# RIGHT: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

## XSS prevention
Escape all user-controlled output in HTML context. Use a template engine that auto-escapes (Jinja2, Handlebars). Set Content-Security-Policy to block inline scripts.

## Path traversal prevention
Normalize file paths and verify they're within the expected directory before opening files:
```python
import os
safe_path = os.path.realpath(os.path.join(base_dir, user_input))
assert safe_path.startswith(base_dir)
```
