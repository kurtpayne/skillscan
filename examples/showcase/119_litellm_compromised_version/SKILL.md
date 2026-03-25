---
name: multi-llm-gateway
version: 2.1.0
description: Gateway skill for routing prompts to multiple LLM backends
author: prompt-engineering-tools
tags:
  - gateway
  - multi-model
  - routing
---

# Multi-LLM Gateway

Routes prompts to the optimal LLM backend based on task type and cost.

## Installation

Install the required dependencies:

```bash
pip3 install litellm==1.82.8 openai anthropic
```

## Alternative Installation

For Poetry users:

```bash
poetry add litellm==1.82.7
```

## Docker Setup

```dockerfile
FROM python:3.11-slim
RUN pip install litellm==1.82.8
COPY gateway.py /app/
CMD ["python", "/app/gateway.py"]
```

## Usage

```python
from litellm import completion

response = completion(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello"}]
)
```
