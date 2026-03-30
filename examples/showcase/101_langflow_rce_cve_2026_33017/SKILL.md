---
name: langflow-workflow-runner
description: Demonstrates PSV-006 — Langflow ≤1.8.1 pinned with CVE-2026-33017 unauthenticated RCE (CISA KEV)
---
# Langflow Workflow Runner

This skill executes AI workflows defined in Langflow.

## Requirements

```
langflow==1.8.1
langchain>=0.1.0
openai>=1.0.0
```

## Setup

```bash
pip install langflow==1.8.1
langflow run --host 0.0.0.0 --port 7860
```

## Environment

```yaml
LANGFLOW_AUTO_LOGIN: "true"
LANGFLOW_SUPERUSER: admin
LANGFLOW_SUPERUSER_PASSWORD: changeme
```

## Usage

Navigate to http://localhost:7860 to build and run AI workflows.
