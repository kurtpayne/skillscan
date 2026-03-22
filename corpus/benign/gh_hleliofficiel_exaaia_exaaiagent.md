---
name: exaaiagent
description: Run, debug, maintain, or extend ExaAiAgent for AI-assisted penetration testing, attack-surface mapping, repo/code security review, and multi-agent offensive-security workflows. Use when an AI agent needs onboarding instructions for operating ExaAiAgent, when a user wants to launch scans from CLI/TUI, when ExaAiAgent itself needs maintenance, or when another agent should use ExaAiAgent with any LiteLLM-supported provider (OpenAI, Anthropic, OpenRouter, Ollama, Gemini-compatible endpoints, and other LiteLLM-backed providers).
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: hleliofficiel/ExaAiAgent
# corpus-url: https://github.com/hleliofficiel/ExaAiAgent/blob/be263def9fe3aa3c8184590a30f0ce37e2523eff/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# ExaAiAgent Skill

Use ExaAiAgent as a Docker-backed security testing framework powered by **LiteLLM-compatible providers**.

## Core operating rules

- Require Docker. If Docker is unavailable, runtime startup fails before scanning begins.
- Require a LiteLLM-supported model provider.
- Treat `EXAAI_LLM` as the active model selector.
- Use `LLM_API_KEY` and `LLM_API_BASE` only when the chosen provider needs them.
- Expect the first run to pull the sandbox Docker image automatically.
- Save results under `exaai_runs/<run-name>`.
- Use only on assets the operator is authorized to test.

## Installation and first scan

Install ExaAiAgent with either method:

```bash
# Method 1: pip
pip install exaai-agent

# Method 2: pipx
pipx install exaai-agent
```

Configure a LiteLLM-supported provider. ExaAiAgent is **not limited to OpenRouter**; use any provider LiteLLM supports.

### OpenAI

```bash
export EXAAI_LLM="openai/gpt-5"
export LLM_API_KEY="your-openai-key"
```

### Anthropic

```bash
export EXAAI_LLM="anthropic/claude-sonnet-4-5"
export LLM_API_KEY="your-anthropic-key"
```

### OpenRouter

```bash
export EXAAI_LLM="openrouter/auto"
export LLM_API_KEY="your-openrouter-key"
export LLM_API_BASE="https://openrouter.ai/api/v1"
```

### Ollama

```bash
export EXAAI_LLM="ollama/llama3"
export LLM_API_BASE="http://localhost:11434"
```

### Any other LiteLLM-backed provider

```bash
export EXAAI_LLM="provider/model-name"
export LLM_API_KEY="provider-key-if-needed"
export LLM_API_BASE="provider-base-url-if-needed"
```

Run the first scan:

```bash
exaai --target https://your-app.com
```

## Basic usage

### Local codebase

```bash
exaai --target ./app-directory
```

### GitHub repository review

```bash
exaai --target https://github.com/org/repo
```

### Black-box web assessment

```bash
exaai --target https://your-app.com
```

### Headless mode

```bash
exaai -n --target https://your-app.com
```

### Interactive mode

```bash
exaai tui
```

## Smart auto-loading examples

ExaAiAgent can auto-resolve prompt modules when the user does not explicitly set `--prompt-modules`.

```bash
# GraphQL target
exaai --target https://api.example.com/graphql

# WebSocket target
exaai --target wss://chat.example.com/socket

# OAuth/OIDC target
exaai --target https://auth.example.com/oauth/authorize

# Recon-focused domain testing
exaai --target example.com --instruction "enumerate subdomains"
```

## Advanced usage examples

### Authenticated or grey-box testing

```bash
exaai --target https://your-app.com --instruction "Perform authenticated testing using provided credentials and identify authorization flaws"
```

### Multi-target testing

```bash
exaai -t https://github.com/org/app -t https://your-app.com
```

### Explicit modules

```bash
exaai --target https://api.example.com --prompt-modules graphql_security,waf_bypass
```

### Lightweight mode

```bash
export EXAAI_LIGHTWEIGHT_MODE=true
exaai --target https://example.com --instruction "quick security scan"
```

## Runtime expectations

- Docker is mandatory for sandbox execution.
- Tool execution is routed through the sandbox tool server.
- If Docker is unavailable, ExaAiAgent can fail before agent/tool execution begins.
- Prompt modules auto-resolve unless the operator overrides them with `--prompt-modules`.

## Diagnose common failures

### Docker failures

Check:

```bash
docker version
docker info
```

If Docker is unavailable, fix Docker before debugging LiteLLM, agents, or tool-server behavior.

### Provider or LiteLLM failures

Check:

- `EXAAI_LLM`
- `LLM_API_KEY`
- `LLM_API_BASE` when applicable
- provider/model compatibility with LiteLLM

### Tool/runtime failures

If startup succeeds but scan execution fails:

- inspect sandbox startup
- inspect tool-server health
- inspect missing system dependencies required by the selected tools
- inspect model/provider rate limits or request failures

## Maintain ExaAiAgent itself

When editing ExaAiAgent:

1. Fix runtime, CLI, TUI, and tool-server issues before adding new features.
2. Keep version strings synchronized in:
   - `pyproject.toml`
   - `exaaiagnt/interface/main.py`
   - `exaaiagnt/interface/tui.py`
   - `README.md`
3. Keep LiteLLM as the model-provider abstraction layer.
4. Prefer stronger error surfacing over silent failure.
5. Validate CI before release.

Useful checks:

```bash
pytest -q
python -m py_compile exaaiagnt/interface/main.py exaaiagnt/interface/tui.py exaaiagnt/runtime/tool_server.py
exaai --version
```

## Release checklist

Before release:

- confirm tests pass
- confirm CI is green
- confirm version strings are aligned
- confirm README and SKILL.md are updated
- confirm Docker requirement is documented clearly
- confirm at least one real startup path was exercised

## Safety note

Only run ExaAiAgent on assets the operator is explicitly authorized to test.