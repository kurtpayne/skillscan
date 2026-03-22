---
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: bcharleson/nemoclaw-macmini-setup
# corpus-url: https://github.com/bcharleson/nemoclaw-macmini-setup/blob/3891c7b64061e73880d12b5191669c3caf778f30/claude-skill.md
# corpus-round: 2026-03-20
# corpus-format: plain_instructions
---
# NemoClaw Mac Mini Setup - Claude Skill

## Description

Guide users through setting up a NemoClaw agent on a Mac Mini with a dedicated user account, dual-layer sandboxing (macOS user isolation + NemoClaw/OpenShell container), and Ollama Cloud inference.

## When to Use This Skill

Invoke this skill when users ask about:
- Setting up NemoClaw on Mac Mini
- Creating isolated AI agent accounts on macOS
- Configuring NemoClaw with OpenShell
- NemoClaw security best practices
- Multiple agent setups on the same machine
- Ollama Cloud inference setup
- Sandboxed AI agent environments

## Instructions

When a user requests NemoClaw setup assistance:

1. **Understand their goal:**
   - Single agent or multiple agents?
   - What's the agent name and username?
   - What Mac Mini model do they have? (M1/M2/M4, RAM amount)
   - Do they already have Colima/Docker installed?
   - Do they already have Ollama installed?

2. **Guide them through the setup:**
   - Reference the [AGENT-SETUP.md](./AGENT-SETUP.md) guide
   - Help them fill in the variables section:
     - AGENT_NAME: Display name (e.g., "EVE", "WALL-E")
     - AGENT_USERNAME: Lowercase username
     - UNIQUE_ID: Auto-detect or specify (502, 503, etc.)
     - ADMIN_USERNAME: Their admin username

3. **Walk through each part:**
   - Part 1: Install host prerequisites (Colima, Docker, Ollama)
   - Part 2: Create sandboxed macOS user (dscl commands)
   - Part 3: Install NemoClaw as agent user (installer + onboarding wizard)
   - Part 4: Verify setup (status, connect, test)
   - Part 5: (Optional) Admin access and symlinks
   - Part 6: (Optional) Auto-start on boot (launchd plists)
   - Part 7: (Optional) Multiple agents

4. **Help with onboarding wizard choices:**
   - Sandbox name: any name they like (default: `my-assistant`)
   - Inference: Select option 2 (Local Ollama) — routes through local Ollama to cloud
   - Model: `nemotron-3-super:cloud` — free tier, runs via Ollama's cloud
   - Security policies: Accept defaults, customize later if needed

5. **Security reminders:**
   - Explain the dual-layer security model (see [SECURITY.md](./SECURITY.md))
   - Layer 1: macOS user isolation (no admin, no sudo)
   - Layer 2: NemoClaw/OpenShell container (Landlock, seccomp, network namespace)
   - Do NOT change ownership of NemoClaw config dirs
   - Use `openshell term` to monitor network egress
   - Recommend strong passwords for agent user accounts
   - Recommend FileVault for disk encryption

6. **Colima resource guidance:**
   - 16 GB Mac Mini: `--cpu 4 --memory 8 --disk 40`
   - 32 GB+ Mac Mini: `--cpu 6 --memory 12 --disk 60`
   - Don't allocate more than 50% of host RAM to Colima

7. **Troubleshooting:**
   - "Cannot connect to Docker daemon" → `colima start`
   - "nvidia-smi not found" → Expected on Apple Silicon, skip
   - "Ollama not reachable from sandbox" → Check `brew services list | grep ollama`
   - "User already exists" → Check/change UNIQUE_ID
   - "Permission denied" → Re-run ownership commands
   - Sandbox creation fails → `docker run hello-world` to test Docker

## Example Usage

**User:** "How do I set up NemoClaw on my Mac Mini?"

**Agent:** "I'll help you set up NemoClaw on your Mac Mini with dual-layer sandboxing! This creates a dedicated user account for your agent and runs it inside NemoClaw's secure container.

First, let's gather some info:
1. What would you like to name your agent? (e.g., 'EVE', 'WALL-E')
2. Which Mac Mini model do you have? (M1/M2/M4, and how much RAM?)
3. Do you already have Docker or Colima installed?
4. Do you already have Ollama installed?

Once we have these, I'll walk you through the setup — it takes about 30-45 minutes and we'll set up:
- A sandboxed macOS user (Layer 1: OS isolation)
- NemoClaw with OpenShell (Layer 2: container sandboxing)
- Nemotron 3 Super via Ollama Cloud (free inference)

Let's get started!"

## Files

- `AGENT-SETUP.md`: Complete setup guide with all commands
- `SECURITY.md`: Dual-layer security model explained
- `README.md`: Quick overview, architecture diagram, and prerequisites
- `claude-skill.md`: This skill documentation

## Repository

https://github.com/bcharleson/nemoclaw-macmini-setup