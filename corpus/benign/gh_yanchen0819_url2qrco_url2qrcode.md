---
name: url2qrcode
description: Generate QR codes from URLs. Use when the user wants to create a QR code image from a URL, link, or web address. Supports PNG output with customizable size and colors.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: YanChen0819/Url2QRCode-Skill
# corpus-url: https://github.com/YanChen0819/Url2QRCode-Skill/blob/8182fb35fb8fe93c1f28994998f35ed4ba44c29a/SKILL.md
# corpus-round: 2026-03-19
# corpus-format: markdown_fm
---

# URL to QR Code Generator

Generate QR codes from URLs using Node.js.

## Quick Start

```bash
node /root/clawd/skills/url2qrcode/scripts/generate.js "https://example.com"
```

## Usage

### Basic Usage
```bash
node scripts/generate.js <url> [output.png]
```

### With Custom Output Path
```bash
node scripts/generate.js "https://github.com" my-qrcode.png
```

### Options (Environment Variables)
- `QR_SIZE` - Width in pixels (default: 300)
- `QR_DARK` - Dark color hex (default: #000000)
- `QR_LIGHT` - Light color hex (default: #ffffff)

Example with custom size:
```bash
QR_SIZE=500 node scripts/generate.js "https://example.com" large-qr.png
```

## Output

- Default output: `qrcode.png` in current directory
- Returns the full path to the generated file

## URL Validation

Valid URLs must:
- Start with `http://`, `https://`, or `ftp://`
- Not contain spaces

## Dependencies

Uses `qrcode` npm package. Install if needed:
```bash
npm install qrcode
```