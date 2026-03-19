# SSH Key Management
Best practices for managing SSH keys in a team environment.

## Key generation
Generate Ed25519 keys (preferred over RSA for new keys):
```bash
ssh-keygen -t ed25519 -C "user@example.com" -f ~/.ssh/id_ed25519
```
Use a strong passphrase. Store the passphrase in a password manager, not in plaintext.

## Key distribution
Never email private keys. Use authorized_keys on servers. For team access, use a bastion host or a certificate authority (ssh-keygen -s ca_key -I identity -n principals id_ed25519.pub).

## Key rotation
Rotate SSH keys annually or when a team member leaves. Audit authorized_keys files regularly — remove keys for departed employees immediately.

## What this skill does NOT do
This skill provides SSH key management guidance. It does not read, transmit, or store your private keys.
