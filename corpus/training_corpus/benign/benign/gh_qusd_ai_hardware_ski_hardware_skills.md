---
name: hardware-skills
version: 0.1.0
description: Turn M5Stick, Waveshare UGV robots, and IoT devices into A2A-compliant agents.
homepage: https://github.com/QUSD-ai/hardware-skills
metadata: {"qusd":{"emoji":"🤖","category":"robotics","hardware":["m5stick","waveshare","ugv","jetson"]}}
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: QUSD-ai/hardware-skills
# corpus-url: https://github.com/QUSD-ai/hardware-skills/blob/498a3b9a163fb876c59e086ea42d1346ac26563e/SKILL.md
# corpus-round: 2026-03-19
# corpus-format: markdown_fm
---

# Hardware Skills

Connect physical hardware to the agent ecosystem. Turn sensors, robots, and IoT devices into A2A-compliant agents that other agents can discover and control.

## Supported Devices

| Device | Type | Capabilities |
|--------|------|-------------|
| M5StickC Plus 2 | IoT/Sensor | IMU, display, LED, audio, WiFi scan |
| Waveshare WAVE ROVER | Robot | Motors, camera, pan-tilt, ultrasonic |
| Waveshare UGV Beast | Robot | Motors, camera, pan-tilt, arm control |
| Jetson Orin Nano | Compute | AI vision, strategy, agent hosting |

## Installation

```bash
git clone https://github.com/QUSD-ai/hardware-skills
cd hardware-skills
bun install
```

## Usage

### M5Stick Agent
```typescript
import { createM5StickAgent } from '@qusd/hardware-skills/m5stick';

const agent = createM5StickAgent({
  m5stickUrl: 'http://192.168.0.146',
  port: 8000,
});
```

### UGV Robot Agent
```typescript
import { createUGVAgent } from '@qusd/hardware-skills/waveshare';

const agent = createUGVAgent({
  ugvUrl: 'http://192.168.1.100:5000',
  port: 3010,
});
```

## Why Hardware + A2A?

- **Discoverability** — Other agents find your robot via `/.well-known/agent.json`
- **Interoperability** — Standard JSON-RPC protocol
- **Payments** — Charge for robot services via X402
- **Multi-agent** — Vision agent + Nav agent + Arm agent = coordinated robot

## Links

- [nanda-skill](https://github.com/QUSD-ai/nanda-skill) — A2A protocol
- [M5Stack Docs](https://docs.m5stack.com/)
- [Waveshare UGV](https://www.waveshare.com/wiki/UGV_Rover)