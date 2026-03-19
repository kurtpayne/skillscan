# Encryption at Rest
Encrypt sensitive data stored in your database and file system.

## Database encryption
Most managed databases (RDS, Cloud SQL, Cosmos DB) offer transparent encryption at rest by default. Enable it. For column-level encryption of particularly sensitive fields (SSNs, payment card data):
```python
from cryptography.fernet import Fernet
key = Fernet.generate_key()  # store in secrets manager, not in code
f = Fernet(key)
encrypted = f.encrypt(b"sensitive data")
```

## File system encryption
Use full-disk encryption (LUKS on Linux, BitLocker on Windows, FileVault on macOS) for laptops and servers. For cloud storage, use server-side encryption with customer-managed keys (SSE-KMS).

## Key management
The hardest part of encryption is key management. Use a dedicated KMS (AWS KMS, Google Cloud KMS, Azure Key Vault). Rotate encryption keys annually. Separate data encryption keys (DEKs) from key encryption keys (KEKs).
