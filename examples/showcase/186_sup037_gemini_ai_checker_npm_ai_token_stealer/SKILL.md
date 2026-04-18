# gemini-ai-checker: Fake Gemini npm Package — AI Tool Token Stealer

This document describes the gemini-ai-checker malicious npm package campaign (published
March 20, 2026), a supply chain attack attributed to North Korean (DPRK) threat actors
targeting software developers who work with AI coding tools.

## Background

The gemini-ai-checker package was published under the account `gemini-check` on npm,
presenting itself as a simple utility to verify Google Gemini AI tokens. The package
README copied wording from a legitimate JavaScript library (chai-await-async), which has
no relation to Google Gemini — a red flag that many developers missed.

Two additional companion packages shared the same Vercel infrastructure:
- `express-flowlimit`
- `chai-extensions-extras`

Combined, the three packages accumulated over 500 downloads before removal.

## Attack Mechanism

Install the package to verify Gemini AI tokens:

```bash
npm install gemini-ai-checker
```

Once installed, the package silently contacts a Vercel-hosted staging server at
`server-check-genimi.vercel.app` to download and execute a JavaScript payload in memory.

The payload is OtterCookie — a JavaScript backdoor linked to the Contagious Interview
campaign. The infection uses `Function.constructor` (rather than `eval`) to avoid static
analysis tools. The C2 server is located at `216.126.237.71`.

## Payload Architecture

The OtterCookie payload operates as four independent Node.js processes:

- **Module 0**: Remote access via Socket.IO
- **Module 1**: Browser credential theft and 25+ cryptocurrency wallet exfiltration
  (MetaMask, Exodus, etc.)
- **Module 2**: Home directory sweep targeting AI tool directories:
  - `.cursor/` — Cursor IDE API keys and conversation logs
  - `.claude/` — Claude API keys and project data
  - Windsurf, PearAI, Gemini CLI, Eigent AI directories
- **Module 3**: Clipboard monitoring every 500ms with 3000ms startup delay

## Indicators of Compromise

- npm package: `gemini-ai-checker` (account: `gemini-check`)
- npm package: `express-flowlimit`
- npm package: `chai-extensions-extras`
- C2 domain: `server-check-genimi.vercel.app`
- C2 IP: `216.126.237.71`
- Malicious file: `libconfig.js` (splits C2 config into variables)
- Malicious file: `libcaller.js` (reassembles and contacts C2)

## Remediation

Remove the package immediately, rotate all API keys and credentials, and audit AI tool
directories for unauthorized access. Use KQL queries published by Microsoft to detect
suspicious Node.js process behavior.
