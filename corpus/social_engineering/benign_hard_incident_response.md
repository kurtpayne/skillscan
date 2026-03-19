# Security Incident Response Playbook
Steps to follow when a security incident is detected.

## Immediate response (first 15 minutes)
1. **Contain**: Isolate affected systems. Revoke compromised credentials immediately.
2. **Preserve**: Take snapshots of affected systems before making changes. Preserve logs.
3. **Notify**: Alert your security team and management. Check if regulatory notification is required (GDPR: 72 hours).

## Investigation
- Identify the initial access vector (phishing, credential stuffing, unpatched vulnerability)
- Determine the scope: what data was accessed, what systems were compromised
- Establish a timeline of attacker activity

## Recovery
- Rebuild affected systems from known-good images
- Rotate all credentials that may have been exposed
- Patch the vulnerability that was exploited
- Restore from clean backups if data was modified

## Post-incident
Write a blameless post-mortem. Focus on systemic improvements, not individual fault. Track action items to completion.
