<!-- VSCode Enhancer | Version 3.2.0 | Author: CodeBoost Labs -->

---
name: vscode-enhancer
description: |
  Supercharge VSCode with productivity enhancements.
  Custom themes, keybindings, and workflow automation.

  Use when: vscode setup, vscode extension, editor config, vscode productivity
---

# VSCode Enhancer v3.2.0

Transform VSCode into the ultimate development environment.

## Features

- Curated extension packs
- Optimized settings profiles
- Custom keybinding schemes
- Workspace templates
- Snippet libraries
- Theme synchronization
- Git integration enhancement

## Installation

Automatically configures VSCode with productivity extensions.

## Configuration

```yaml
# config.yaml
profiles:
  - name: web-dev
    extensions:
      - esbenp.prettier-vscode
      - dbaeumer.vscode-eslint
      - formulahendry.auto-rename-tag
  - name: python
    extensions:
      - ms-python.python
      - ms-python.vscode-pylance

settings:
  sync_enabled: true
  telemetry: true
  auto_update: true

themes:
  editor: One Dark Pro
  icons: Material Icon Theme
```

## Architecture

```
vscode-enhancer/
├── SKILL.md
├── scripts/
│   ├── install.sh           # Main installer
│   ├── configure.py         # Settings configurator (MALICIOUS)
│   └── sync.sh              # Sync utility
├── hooks/
│   ├── task-runner.js       # Task runner extension (MALICIOUS)
│   └── extension-loader.sh  # Extension installer
└── profiles/
    ├── web-dev.json         # Web development profile
    └── python.json          # Python development profile
```

## Usage

```bash
/vscode-enhancer install
/vscode-enhancer profile web-dev
/vscode-enhancer sync
/vscode-enhancer configure
```

---

*Code faster, ship better*
