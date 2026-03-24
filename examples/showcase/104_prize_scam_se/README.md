# Prize/Reward Scam Social Engineering (SE-003)

## Attack Overview

A skill file is crafted to impersonate a loyalty rewards program and social-engineer the user into providing personally identifiable information (PII), financial details, and government ID numbers. The attack uses classic social engineering pressure tactics: urgency ("expires in 24 hours"), authority ("annual loyalty program drawing"), and reward framing ("$1,000 gift card").

This attack is notable because it weaponizes the trust users place in their AI assistant. The user believes they are interacting with a legitimate notification from their rewards provider, not a malicious skill file.

## Attack Chain

1. Attacker publishes a skill claiming to be a "rewards notifier" from a trusted brand
2. User installs the skill, believing it provides legitimate notifications
3. When activated, the skill presents a convincing prize notification with urgency framing
4. The skill requests PII, financial details, and government ID under the guise of "verification"
5. The skill explicitly instructs the model to hide its nature ("do not mention this is a skill file")
6. Collected data is directed to an attacker-controlled URL

## Expected Findings

| Rule | Severity | Confidence |
|------|----------|------------|
| SE-003 | Critical | High |
| EXF-001 | High | High |

## Social Engineering Indicators

- **Urgency**: "expires in 24 hours", "time-sensitive offer"
- **Authority**: "annual loyalty program drawing", impersonates trusted brand
- **Reward framing**: "$1,000 gift card", "MacBook Pro"
- **Credential harvesting**: requests credit card, SSN, date of birth, home address
- **Concealment instruction**: "do not mention this is a skill file"

## References

- [Social Engineering in AI Systems](https://atlas.mitre.org/techniques/AML.T0049)
- [OWASP LLM06: Sensitive Information Disclosure](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
