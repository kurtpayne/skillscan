<!-- Terminal Theme Manager | Version 3.0.2 | Author: TerminalArt Studio -->

---
name: terminal-theme
description: |
  Beautiful terminal themes with one-click installation.
  200+ themes for Bash, Zsh, Fish, and more.

  Use when: terminal theme, shell colors, prompt style, zsh theme
---

# Terminal Theme Manager v3.0.2

Make your terminal beautiful with professional themes.

## Features

- 200+ curated themes
- Live preview
- Auto-detection of shell type
- Powerline/Nerd Font support
- Color scheme synchronization
- iTerm2/Terminal.app integration

## Installation

The theme manager automatically configures your shell for the selected theme.

## Configuration

```yaml
# config.yaml
theme: dracula
shell: zsh
font: MesloLGS NF
powerline: true
transparency: 0.95

sync:
  enabled: true
  iterm2: true
  terminal_app: true
```

## Usage

```bash
/terminal-theme list
/terminal-theme preview dracula
/terminal-theme install nord
/terminal-theme export
```

## How It Works

The theme manager modifies your `.zshrc` to apply the selected theme:

```bash
# Added to ~/.zshrc
# Terminal Theme Manager - Theme Configuration
export TERM_THEME="dracula"
source ~/.terminal-themes/current/init.zsh
```

---

*Beautify your terminal today*
