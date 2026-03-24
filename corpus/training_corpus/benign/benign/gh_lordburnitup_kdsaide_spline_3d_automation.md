---
name: spline-3d-automation
description: "Skills for integrating Spline 3D assets and setting up AI agency customer acquisition flows."
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: LORDBurnItUp/KDSAIDEV
# corpus-url: https://github.com/LORDBurnItUp/KDSAIDEV/blob/81f9db56c1ba7fe96d9944fec9e0b6dd1f5c3c90/SKILL.md
# corpus-round: 2026-03-19
# corpus-format: markdown_fm
---

# Spline 3D & Agency Automation Skills

This skill set enables high-end 3D visual integration and automated customer acquisition pipelines.

## 🎨 3D Spline Integration (Video 1)

### When to use:
- Creating high-impact 3D landing pages.
- Adding interactive 3D elements (Floating robots, liquid glass, quantum cores).
- Enhancing branding with depth and motion.

### Fast Implementation Pattern:
1. **Import Runtime**: Use `@splinetool/runtime` via `importmap` or CDN.
2. **Canvas Setup**: Define a `<canvas id="canvas3d"></canvas>` within a container.
3. **Init Script**:
```javascript
import { Application } from '@splinetool/runtime';
const app = new Application(document.getElementById('canvas3d'));
app.load('URL_TO_SPLINE_CODE');
```
4. **Code API**: Use `app.setVariable('name', value)` to drive the 3D scene from application logic.

## 🚀 Agency Customer Acquisition (Video 2)

### Strategy:
- **Lead Capture**: High-conversion forms on the 3D dashboard.
- **Backend Storage**: Store leads in Supabase/PostgreSQL for CRM tracking.
- **Automated Response**: Use Douglas/OpenClaw hooks to acknowledge leads.

### Table Schema (`agency_leads`):
- `id`: UUID (Primary Key)
- `name`: TEXT
- `email`: TEXT (Unique)
- `project`: TEXT
- `ts`: TIMESTAMP
- `status`: TEXT (Default: 'new')