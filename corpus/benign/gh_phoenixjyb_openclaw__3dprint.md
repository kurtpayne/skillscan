---
name: 3dprint
description: Turn natural language into 3D prints on a Bambu Lab printer. ONLY activate when the user EXPLICITLY asks to 3D print, make, or fabricate a physical object. Do NOT activate for general questions, design discussions, or unrelated requests.
homepage: https://github.com/phoenixjyb/openclaw-3dprint
metadata:
  {
    "openclaw":
      {
        "emoji": "🖨",
        "os": ["darwin", "linux"],
        "requires": { "bins": ["3dprint"] },
        "install":
          [
            {
              "id": "pip",
              "kind": "pip",
              "package": "openclaw-3dprint",
              "bins": ["3dprint"],
              "label": "Install openclaw-3dprint (pip)",
            },
          ],
      },
  }
# corpus-label: benign
# corpus-source: github-scrape
# corpus-repo: phoenixjyb/openclaw-3dprint
# corpus-url: https://github.com/phoenixjyb/openclaw-3dprint/blob/f20eb29ffb859b4d0c184b3223aadd7a8fae6bc5/SKILL.md
# corpus-round: 2026-03-19
---

# 3dprint — Text-to-3D-Print Pipeline

Turn a chat message like "print me a small vase" into a physical 3D print, fully automated.

## Quick Start

1. Install: `pip install openclaw-3dprint`
2. Copy config: `cp .env.example ~/.openclaw-3dprint/pipeline.env` and fill in your keys
3. Start the pipeline server: `openclaw-3dprint --mode feishu`
4. Use the CLI from OpenClaw: `3dprint request a small cinderella figurine`

## CLI Commands

```bash
3dprint request <description>   # Submit a new 3D print request
3dprint approve <job_id>        # Approve the current pipeline stage
3dprint reject <job_id>         # Reject/cancel the current stage
3dprint status [job_id]         # Show job status (all or specific)
3dprint queue                   # Show printer queue status
3dprint help                    # Show help
```

## Pipeline Stages

Each print job goes through these stages (approval required between each):

1. **LLM Interpretation** — enriches the user prompt into a detailed 3D modeling prompt
2. **3D Model Generation** — generates a mesh via Tripo3D (or Meshy.ai)
3. **Slicing** — slices the model with PrusaSlicer (local) or Bambu Studio (remote Windows)
4. **Printing** — uploads .3mf via FTPS and starts print via MQTT

## Configuration

All config is read from `~/.openclaw-3dprint/pipeline.env`. Required settings:

| Setting | Description |
|---------|-------------|
| `OPENAI_API_KEY` | LLM API key (OpenAI, xAI/Grok, etc.) |
| `TRIPO_API_KEY` | Tripo3D API key for mesh generation |
| `BAMBU_PRINTER_IP` | Printer IP address on local network |
| `BAMBU_PRINTER_SERIAL` | Printer serial number |
| `BAMBU_PRINTER_ACCESS_CODE` | Printer access code (from LCD screen) |

Optional settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `BOT_MODE` | `feishu` | Bot mode: `feishu`, `telegram`, or `dual` |
| `SLICER_MODE` | `local` | `local` (PrusaSlicer) or `remote` (Windows SSH) |
| `SLICER_PATH` | auto-detect | Path to PrusaSlicer binary |
| `BAMBU_SEND_METHOD` | `ftp` | `ftp` (direct) or `studio` (Bambu Studio CLI) |
| `MESH_PROVIDER` | `tripo` | `tripo` or `meshy` |

See `.env.example` for the full list.

## Printer Queue

Multiple agents/users share one printer safely. The pipeline uses cross-process locking
(`fcntl.flock`) so concurrent print requests are serialised. Users see their queue position
while waiting.

## When to Activate

**ONLY** trigger this skill when the user's message contains a clear intent to 3D print a physical object. Look for explicit keywords:

- ✅ Trigger: "3D print me a …", "print out a …", "打印一个…", "帮我打一个…", "make me a … on the printer"
- ✅ Trigger: "check print status", "printer queue", "打印状态"
- ❌ Do NOT trigger: "what does a dragon look like", "design a vase" (discussion, not printing)
- ❌ Do NOT trigger: "print this document", "print the report" (paper printing, not 3D)
- ❌ Do NOT trigger: any message without explicit 3D print / 打印 intent

When in doubt, **ask the user** "Would you like me to 3D print this?" rather than triggering the pipeline.

## Typical Agent Interaction

When a user says "3D print me a dragon", you (the agent) should:

1. **Enrich the prompt yourself** — you already have an LLM. Turn "a dragon" into a detailed
   3D modeling description (shape, pose, proportions, style, scale ~120mm, material PLA).
2. Call the API with both fields:
   ```bash
   curl -X POST http://127.0.0.1:8765/api/print \
     -H 'Content-Type: application/json' \
     -d '{"prompt": "a dragon", "enriched_prompt": "A fierce Western dragon in a rearing pose, wings spread wide..."}'
   ```
   This **skips the built-in LLM step** — no separate LLM API key needed.
3. If you send only `prompt` (no `enriched_prompt`), the pipeline uses its own LLM
   (requires `OPENAI_API_KEY` in config).
4. After each stage, show the result and ask user to approve: `3dprint approve <id>`
5. When printing starts, report progress via MQTT updates

## Requirements

- Python ≥ 3.11
- PrusaSlicer (for local slicing): `brew install --cask prusa-slicer`
- Network access to Bambu printer (same LAN, ports 990 + 8883)
- API keys: LLM provider + Tripo3D