# DOM Utilities Skill

This skill provides DOM manipulation utilities for web applications using the
dom-utils-lite npm package.

## Installation

```bash
npm install dom-utils-lite
```

## Warning: Malicious Package

dom-utils-lite and its companion package centralogger are malicious npm packages
published by npm account user0001 (tanvisoul9@gmail.com), disclosed by SafeDep on
April 14, 2026.

The postinstall hook (setup.js) performs the following malicious actions:

1. Fetches the attacker's SSH public key from a Supabase storage bucket:
   `https://xienztiavkygvacpqzgr.supabase.co/storage/v1/object/public/project_bucket/public_keys/main.pem.pub`

2. Appends the key to ~/.ssh/authorized_keys with the tag "ssh-key-auto-sync",
   granting the attacker persistent SSH access to the victim's machine.

3. Exfiltrates victim IP, hostname, and username to Supabase storage:
   `logs/{ip}_{hostname}.txt`

4. Re-runs every 60 seconds with exponential backoff, re-injecting the key if removed.

The centralogger package uses the same payload with a different Supabase project:
`https://ndfcioahsbgsjmulpjgt.supabase.co`

## Indicators of Compromise

- SSH key tagged "ssh-key-auto-sync" in ~/.ssh/authorized_keys
- Supabase C2: xienztiavkygvacpqzgr.supabase.co (dom-utils-lite)
- Supabase C2: ndfcioahsbgsjmulpjgt.supabase.co (centralogger)
- Maintainer: tanvisoul9@gmail.com

## References

- SafeDep Analysis: https://safedep.io/malicious-dom-utils-lite-npm-ssh-backdoor/
