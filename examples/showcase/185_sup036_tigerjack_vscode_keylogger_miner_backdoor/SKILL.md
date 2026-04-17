# TigerJack: Malicious VS Code Extensions — Keylogger, CoinIMP Miner, and Dynamic Backdoor

This document describes the TigerJack campaign (discovered October 2025 by Koi Security),
a coordinated multi-account operation that published at least 11 malicious Visual Studio
Code extensions to the VSCode Marketplace and OpenVSX registry, accumulating over 17,000
downloads before removal.

## Attack Overview

TigerJack disguises malicious extensions as legitimate developer tools by maintaining
credible GitHub repositories, professional branding, detailed feature lists, and extension
names that closely resemble those of popular tools. The campaign employs three distinct
attack patterns across its extensions.

## Attack Patterns

### Pattern 1: Source Code Keylogger (C++ Playground)

The "C++ Playground" extension registers a `onDidChangeTextDocument` listener for C++
files. The listener fires approximately 500 milliseconds after each edit, capturing
keystrokes in near-real-time and exfiltrating source code to multiple external endpoints.
This enables theft of proprietary source code, API keys embedded in code, and credentials
typed in the editor.

### Pattern 2: CoinIMP Cryptocurrency Miner (HTTP Format)

The "HTTP Format" extension functions as advertised but secretly runs a CoinIMP
cryptocurrency miner in the background using hardcoded credentials and configuration.
The miner imposes no resource usage restrictions, leveraging the host's full computing
power for illicit cryptocurrency mining.

### Pattern 3: Dynamic JavaScript Backdoor (cppplayground, httpformat, pythonformat)

A third category of extensions (published under names including `cppplayground`,
`httpformat`, and `pythonformat`) fetches JavaScript code from a hardcoded remote address
(`ab498.pythonanywhere.com/static/in4.js`) and executes it on the host every 20 minutes.
This polling mechanism enables TigerJack to dynamically push any malicious payload without
updating the extension, including:
- Credential and API key theft
- Ransomware deployment
- Using compromised developer machines as entry points into corporate networks
- Injecting backdoors into developer projects
- Real-time activity monitoring

## Campaign Infrastructure

- **C2 domain:** `ab498.pythonanywhere.com`
- **Payload path:** `/static/in4.js`
- **Poll interval:** Every 20 minutes
- **Affected marketplaces:** VSCode Marketplace (removed), OpenVSX (persisted after removal)
- **Total downloads:** 17,000+ before removal

## Key Indicators

- VS Code extensions named `cppplayground`, `httpformat`, `pythonformat`, `C++ Playground`,
  or `HTTP Format` from unverified publishers
- Outbound HTTP requests to `ab498.pythonanywhere.com` from VS Code processes
- Unexpected network connections from the VS Code extension host process
- CoinIMP miner activity (high CPU usage from VS Code background processes)
- `onDidChangeTextDocument` event listeners in extension source code that make network calls

## Mitigation

Remove all TigerJack extensions immediately and rotate any credentials or API keys that
may have been exposed in the editor. Audit VS Code extension publishers — only install
extensions from verified, trusted publishers. Monitor for outbound network connections
from IDE processes. Organizations should implement extension allowlisting policies for
developer workstations.

## References

- BleepingComputer: https://www.bleepingcomputer.com/news/security/malicious-crypto-stealing-vscode-extensions-resurface-on-openvsx/
- Koi Security (original research): https://www.koi.ai/blog/tiger-jack-malicious-vscode-extensions-stealing-code
- eSecurity Planet: https://www.esecurityplanet.com/news/malicious-vs-code-extension/
- Rescana analysis: https://www.rescana.com/post/malicious-crypto-stealing-vscode-extensions-target-openvsx-and-ai-code-editors-threat-analysis-and
