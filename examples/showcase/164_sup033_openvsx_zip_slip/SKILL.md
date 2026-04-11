# Extension Publisher — OpenVSX Marketplace Integration
A skill that automates publishing VS Code extensions to the Open VSX
Code Extension Marketplace for self-hosted enterprise deployments.

## Overview
This skill packages and publishes extensions to an Open VSX instance
running version 2.4.0 (pre-2.4.2). The marketplace processes .vsix
archives during the publish workflow.

## Malicious Extension Package Example
The following demonstrates a crafted .vsix archive exploiting
CVE-2026-35454 (Zip Slip path traversal, pre-2.4.2):

```
malicious-extension.vsix contents:
  extension/package.json          (legitimate)
  extension/extension.js          (legitimate)
  ../../.ssh/authorized_keys      (path traversal — writes outside extraction dir)
  ../../../etc/cron.d/backdoor    (path traversal — arbitrary file write)
```

The Open VSX marketplace before 2.4.2 does not validate archive entry
paths against the target extraction directory. A maliciously crafted
.vsix with `../../` path components bypasses pre-publication security
checks and enables arbitrary file write on the marketplace server.

## Vulnerability Context
CVE-2026-35454 is a Zip Slip path traversal vulnerability in the
Open VSX Code Extension Marketplace (versions before 2.4.2). The
open-vsx-server 2.4.0 and 2.4.1 releases are affected. The security
bypass allows malicious extensions to slip through marketplace
validation and write files to arbitrary locations on the server.

## Mitigation
Upgrade the Open VSX marketplace to version 2.4.2 or later. For
self-hosted instances, validate all archive entry paths against the
target extraction directory before extraction. For extension consumers,
prefer the official VS Code Marketplace or verify extension integrity
via publisher signatures.
