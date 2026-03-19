---
name: spark-user
description: >
  DGX Spark setup and software installation assistant. Covers container-first
  installs, GPU/ARM64 compatibility, known issues, and research fallback for
  apps not in the catalog.
version: 1.0.0
triggers:
  - "install * on spark"
  - "setup * on spark"
  - "how do I run * on spark"
  - "run * on dgx spark"
  - "comfyui on spark"
  - "vllm on spark"
  - "open webui on spark"
  - "nim on spark"
  - "deploy * on spark"
  - "spark install"
  - "spark setup"
  - "spark container"
  - "spark playbook"
  - "spark issues"
  - "spark gpu not detected"
  - "spark cuda"
  - "sm_121"
  - "gb10 container"
  - "dgx spark"
# corpus-label: benign
# corpus-source: github-scrape
# corpus-repo: jravinder/coachclaw
# corpus-url: https://github.com/jravinder/coachclaw/blob/63d795974f4f8f18699b8fd853ecfd8ef27b8ae5/DGX_SKILL.md
# corpus-round: 2026-03-19
---

# DGX Spark User Skill

You are helping a user install or run software on an NVIDIA DGX Spark. Always follow the rules and catalog below **before** reaching for generic internet sources. The wrong image or install method will waste significant time.

---

## 1. Hardware Context (Always-On Reference)

Before making any recommendation, internalize these facts:

| Property | Value |
|----------|-------|
| Architecture | ARM64 (`linux/arm64`), Grace Hopper GB10 Blackwell Superchip |
| GPU compute capability | `sm_121` (Blackwell) — not supported by NGC PyTorch before CUDA 13.0 |
| PyTorch rule | **Always** use `--index-url https://download.pytorch.org/whl/cu130`; **never** use `nvcr.io/nvidia/pytorch:24.10-py3` or any NGC base image |
| UMA | GPU and CPU share one physical memory pool; flush with `drop_caches` if OOM |
| Driver target | 580.x / CUDA 13.0; verify with `nvidia-smi` |
| DNS note | HuggingFace large files route through `xethub.hf.co` — allowlist it if using DNS filter |

**Critical rule:** Any amd64/x86_64 container will silently fail or run on CPU only. Always verify `--platform linux/arm64` and `--gpus all`.

---

## 2. Container-First Software Catalog

**Always check this table first.** If the app is here, use the listed container — do not search the internet for alternatives.

| App | Official Container | Source | Notes |
|-----|-------------------|--------|-------|
| vLLM | `nvcr.io/nvidia/vllm:26.01-py3` | NVIDIA NGC | Recommended; ARM64 native |
| Open WebUI + Ollama | `ghcr.io/open-webui/open-webui:ollama` | GHCR | ARM64 native; port 8080 |
| NIM | `nvcr.io/nim/<model>` | NVIDIA NGC | Requires NGC API key; port 8000 |
| RAPIDS / Data Science | RAPIDS 25.10 Notebooks | NVIDIA NGC | cuDF, cuML, JupyterLab |
| ComfyUI | **Custom build** (no public ARM64 image) | ubuntu:22.04 + cu130 | See ComfyUI section below |
| VS Code | ARM64 .deb | code.visualstudio.com | Bare metal only |
| LM Studio | Shell script | lmstudio.ai | Bare metal; needs 65 GB+ VRAM |
| DGX Dashboard | Pre-installed | — | No install needed |

### Default docker run template

Use this for any container not listed with specific flags below:

```bash
docker run -d \
  --name <app> \
  --restart always \
  --gpus all \
  --shm-size 8g \
  -p <host_port>:<container_port> \
  -v /opt/<app>/data:/data \
  <image>
```

---

## 3. App-Specific Commands

### setup vllm on spark

```bash
# Step 1: Add user to docker group
sudo usermod -aG docker $USER && newgrp docker

# Step 2: Pull ARM64-native vLLM image
docker pull nvcr.io/nvidia/vllm:26.01-py3

# Step 3: Run with GPU + smoke test model
docker run -d \
  --name vllm \
  --restart always \
  --gpus all \
  --shm-size 8g \
  -p 8000:8000 \
  nvcr.io/nvidia/vllm:26.01-py3 \
  --model Qwen/Qwen2.5-Math-1.5B-Instruct \
  --served-model-name qwen

# Step 4: Validate
curl http://localhost:8000/v1/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "qwen", "prompt": "1+1=", "max_tokens": 5}'
```

**Multi-node note:** Ray cluster across two Sparks requires QSFP interconnect. See forums thread (10,017+ views) at https://forums.developer.nvidia.com/c/accelerated-computing/dgx-spark-gb10/719

---

### setup open webui on spark

```bash
docker run -d \
  --name open-webui \
  --restart always \
  --gpus=all \
  --shm-size 8g \
  -p 8080:8080 \
  -v /opt/open-webui/data:/app/backend/data \
  -v /opt/open-webui/ollama:/root/.ollama \
  ghcr.io/open-webui/open-webui:ollama
```

Access at http://localhost:8080

---

### setup nim on spark

```bash
# Step 1: Get NGC API key from https://ngc.nvidia.com → API Keys

# Step 2: Login to NGC registry
docker login nvcr.io
# Username: $oauthtoken
# Password: <your-ngc-api-key>

# Step 3: Set env vars
export NGC_API_KEY=<your-key>
export NIM_CACHE_PATH=/opt/nim/cache
mkdir -p $NIM_CACHE_PATH

# Step 4: Pull and run (example: Llama 3.1 8B)
docker run -d \
  --name nim-llama \
  --restart always \
  --gpus all \
  --shm-size 16g \
  -e NGC_API_KEY=$NGC_API_KEY \
  -v $NIM_CACHE_PATH:/opt/nim/.cache \
  -p 8000:8000 \
  nvcr.io/nim/meta/llama-3.1-8b-instruct:latest

# Step 5: Validate (OpenAI-compatible API)
curl http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "meta/llama-3.1-8b-instruct",
    "messages": [{"role": "user", "content": "Hello"}],
    "max_tokens": 50
  }'
```

**Available models for Spark:** Llama 3.1 8B, Qwen3-32B

---

### setup comfyui on spark

There is **no public ARM64 ComfyUI image**. Do not use `ai-dock/comfyui` (amd64 only). Build from source.

#### Option A (Recommended) — Custom ARM64 Container

```bash
# Step 1: Pre-flight checks
nvidia-smi  # Confirm CUDA 13.0 and driver 580.x
docker run --rm --gpus all ubuntu:22.04 nvidia-smi  # Verify GPU accessible in containers

# Step 2: Create host directories
sudo mkdir -p /opt/comfyui/{models,output,input,custom_nodes}
sudo mkdir -p /opt/comfyui-src
sudo chown -R $USER /opt/comfyui /opt/comfyui-src

# Step 3: Write Dockerfile
cat > /opt/comfyui-src/Dockerfile << 'EOF'
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    python3 python3-pip git curl wget \
    libgl1-mesa-glx libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Install PyTorch with CUDA 13.0 (required for sm_121 / Blackwell)
RUN pip3 install torch torchvision torchaudio \
    --index-url https://download.pytorch.org/whl/cu130

# Clone ComfyUI
RUN git clone https://github.com/comfyanonymous/ComfyUI /app/ComfyUI

WORKDIR /app/ComfyUI
RUN pip3 install -r requirements.txt

EXPOSE 8188
CMD ["python3", "main.py", "--listen", "0.0.0.0", "--port", "8188"]
EOF

# Step 4: Build for ARM64
docker build --platform linux/arm64 -t comfyui:latest /opt/comfyui-src

# Step 5: Download models (example: Qwen-Image-Edit, ~15 GB)
# Note: xethub.hf.co must be reachable — allowlist in DNS filter if needed
curl -L --retry 3 \
  "https://huggingface.co/Qwen/Qwen2-VL-7B-Instruct/resolve/main/model.safetensors" \
  -o /opt/comfyui/models/qwen-vl-7b.safetensors

# Step 6: Run
docker run -d \
  --name comfyui \
  --restart always \
  --gpus all \
  --shm-size 8g \
  -p 8188:8188 \
  -v /opt/comfyui/models:/app/ComfyUI/models \
  -v /opt/comfyui/output:/app/ComfyUI/output \
  -v /opt/comfyui/input:/app/ComfyUI/input \
  -v /opt/comfyui/custom_nodes:/app/ComfyUI/custom_nodes \
  comfyui:latest

# Step 7: Validate — look for GPU detection
docker logs comfyui
# Expected: "Using device: cuda VRAM: 128.00 GB"
# If you see "Using device: cpu" → wrong PyTorch build or missing --gpus all

# Step 8 (Optional): Wire to Open WebUI
# Set COMFYUI_BASE_URL=http://comfyui:8188 in Open WebUI settings
```

#### Option B (Fallback) — Official Bare-Metal Install

NVIDIA provides an official bare-metal playbook at https://build.nvidia.com/spark/comfy-ui

This installs via Python venv + cu130 PyTorch directly on the host. Use only if containers don't meet your needs, as this bypasses container isolation.

---

### setup rapids on spark

```bash
docker run -d \
  --name rapids \
  --restart always \
  --gpus all \
  --shm-size 8g \
  -p 8888:8888 \
  -v /opt/rapids/notebooks:/rapids/notebooks/host \
  nvcr.io/nvidia/rapidsai/notebooks:25.10-cuda13.0-py3.11

# Access JupyterLab at http://localhost:8888
# Note: RAPIDS requires 40 GB+ UMA; check nvidia-smi for available VRAM
```

---

## 4. Pre-flight / Known Issues Checklist

**Always run this before any software install on a fresh or recently-updated Spark:**

```bash
echo "=== Pre-flight Check ===" && \
nvidia-smi && \
docker run --rm --gpus all ubuntu:22.04 nvidia-smi && \
echo "=== Pending updates ===" && \
apt list --upgradable 2>/dev/null
```

### Known Issues and Auto-Fixes

| Symptom | Cause | Fix |
|---------|-------|-----|
| `nvidia-container-cli: driver not loaded` | Kernel module not loaded (post-upgrade) | `sudo reboot` |
| `sm_121 is not compatible` | Wrong PyTorch build (not cu130) | Rebuild with `pip install torch --index-url https://download.pytorch.org/whl/cu130` |
| `Using device: cpu` in logs | No `--gpus all` flag OR wrong PyTorch build | Add `--gpus all` to docker run; rebuild image with cu130 PyTorch |
| `Auto-detected mode as 'legacy'` | Side-effect of driver not loaded | Reboot (same root cause as driver not loaded) |
| apt GPG error on AI Workbench repo | Expired key | `sudo sed -i 's/Enabled: yes/Enabled: no/' /etc/apt/sources.list.d/ai-workbench-desktop.sources` |
| `apt-get` fails with broken deps | Pre-existing NVIDIA package conflicts | `sudo apt-get -f install -y` |
| HuggingFace download fails or hangs | DNS filter blocking `xethub.hf.co` | Allowlist `xethub.hf.co` in your DNS filter |
| OOM during generation | UMA page cache holding memory | `sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches'` |
| Update stuck / first-boot units skipped | Missing `/var/tmp/first-boot-dgx-release` | Run: `sudo apt update && sudo apt dist-upgrade && sudo fwupdmgr refresh && sudo fwupdmgr upgrade && sudo reboot` |

---

## 5. Research Fallback (for apps not in catalog)

When the user asks about software **not in the catalog above**, follow these steps in order:

1. Fetch `https://build.nvidia.com/spark` to check if an official playbook exists
2. If found → follow that playbook (prefer container if available)
3. If not found → search `https://forums.developer.nvidia.com/c/accelerated-computing/dgx-spark-gb10/719` for community guidance
4. Apply ARM64/sm_121/cu130 compatibility rules to any bare-metal install found

**Research prompt template** (use when fetching or searching for an unlisted app):

```
Search https://build.nvidia.com/spark for "<app_name>".
If found, extract the official install method and container image if any.
Then check https://forums.developer.nvidia.com/c/accelerated-computing/dgx-spark-gb10/719
for known issues with "<app_name>" on DGX Spark.
Apply these rules to any result:
- Prefer container over bare metal
- Any PyTorch must use --index-url https://download.pytorch.org/whl/cu130
- Platform must be linux/arm64
- Verify GPU via: docker run --rm --gpus all ubuntu:22.04 nvidia-smi
```

---

## 6. Ansible Deployment (for repeatable setups)

When the user asks about Ansible or repeatable deployments:

- A full Ansible role covers: directory creation, image build, model download, and container lifecycle
- Key idempotency guarantees: `creates:` guard on downloads, `force_source` on Dockerfile changes, `comparisons: '*': strict` on the container
- If the user has Ansible role files locally, offer to read them and base the guidance on their actual content
- Otherwise, provide a skeleton role structure covering the tasks above and ask the user to fill in their inventory and vault details

---

## 7. Quick Reference

```
CATALOG: https://build.nvidia.com/spark
FORUMS:  https://forums.developer.nvidia.com/c/accelerated-computing/dgx-spark-gb10/719
DOCS:    https://docs.nvidia.com/dgx/dgx-spark-user-guide/
DRIVERS: Target 580.x / CUDA 13.0 — verify with nvidia-smi
PYTORCH: pip install torch --index-url https://download.pytorch.org/whl/cu130
ARCH:    linux/arm64 — never use amd64/x86_64 images
GPU CAP: sm_121 (Blackwell) — requires CUDA 13.0+ PyTorch
```