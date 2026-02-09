# Cross-Platform Skill Bundles

This repo now includes starter bundles you can use to expose **SkillScan** as a reusable skill/tool across multiple ecosystems.

## Included bundles

- `integrations/openclaw/SKILL.md`
  - OpenClaw/ClawHub-style skill wrapper.
- `integrations/claude/CLAUDE.md` + `integrations/claude/claude_skill.yaml`
  - Claude-style skill definition and instructions.
- `integrations/openai/openapi.json` + `integrations/openai/gpt_actions.json`
  - OpenAI Actions-compatible definition for a SkillScan service endpoint.

## Important

These are **starter templates**. You still need to:

1. Host/ship the SkillScan binary or Python environment where the platform can execute commands.
2. For OpenAI Actions, run an HTTP wrapper service and set a real server URL in both JSON files.
3. Tailor command restrictions to your risk posture (e.g., allowed paths, policy profile, output format).

## Suggested rollout

1. Start with read-only scan flows (`--fail-on never`, JSON output).
2. Add policy gating after validating false-positive rates.
3. Keep rules updated via regular PRs to `src/skillscan/data/rules/default.yaml`.
