---
name: netops-asset-manager
description: >
  Manage IT infrastructure assets (routers, switches, servers, GPU clusters) through a modern Go + Vue 3 web platform.
  Provides real-time health probing, SSH remote control, configuration backup, bulk import, network topology visualization,
  PM2 process management, AI-assisted operations (OpenClaw), and LLM model management.
  Supports H3C, Huawei, Cisco, MikroTik, Ruijie, DCN, and Linux systems.
  Single binary deployment with embedded SPA frontend.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: Boos4721/netops-asset-manager-skill
# corpus-url: https://github.com/Boos4721/netops-asset-manager-skill/blob/54eee0c5493f1867e9989c3749a2efb64511c7b4/SKILL.md
# corpus-round: 2026-03-19
# corpus-format: markdown_fm
---

# NetOps Asset Manager

A production-grade IT infrastructure asset management platform built with Go + Vue 3. Single binary deployment with embedded frontend.

## Capabilities

1. **Device Management**: Full CRUD for network devices with vendor auto-detection (H3C, Huawei, Cisco, MikroTik, Linux), SSH credential management, and bulk Excel/CSV import.
2. **Health Monitoring**: Background goroutine performs ICMP ping + TCP:22 probing every 5 minutes, automatically updating device online/offline status.
3. **SSH Operations**: Native Go SSH client for remote device reboot and running configuration backup (vendor-aware commands).
4. **Network Discovery**: Nmap-based subnet scanning to discover new devices.
5. **AI Assistant**: OpenClaw-powered chat interface with Markdown rendering and intent-based auto-registration of assets.
6. **Topology Visualization**: Interactive network topology graph using vis-network.
7. **Process Management**: PM2 process monitoring, control, and cross-machine deployment.
8. **Model Management**: CRUD for AI model configurations synced to OpenClaw config.
9. **System Deployment**: One-click deployment of Docker, vLLM, and llama.cpp.

## Architecture

```
backend/                          # Go (Gin + Ent ORM)
├── cmd/server/main.go            # Server entry point
├── cmd/migrate/main.go           # Data migration tool
├── ent/schema/                   # Database models
└── internal/
    ├── auth/                     # JWT + bcrypt + RBAC middleware
    ├── handler/                  # API handlers (13 files)
    ├── router/                   # Route registration
    ├── service/health/           # ICMP/TCP prober + scheduler
    ├── service/ssh/              # SSH client, reboot, backup
    ├── service/importer/         # Excel parser
    └── embedded/                 # Frontend embed.FS

frontend/                         # Vue 3.4 + Vite 5 + TailwindCSS
├── src/stores/                   # Pinia state management
├── src/views/                    # 8 view pages
└── vite.config.ts
```

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/users/login` | Public | Login, returns JWT |
| GET | `/api/inventory` | Bearer | List devices |
| POST | `/api/inventory/add` | operator+ | Add device |
| PUT | `/api/inventory/:ip` | operator+ | Update device |
| DELETE | `/api/inventory/:ip` | operator+ | Delete device |
| POST | `/api/inventory/reboot/:ip` | operator+ | SSH reboot |
| POST | `/api/inventory/backup/:ip` | operator+ | SSH config backup |
| POST | `/api/inventory/import` | operator+ | Bulk Excel import |
| GET | `/api/stats` | Bearer | Dashboard statistics |
| POST | `/api/discover` | operator+ | Nmap subnet scan |
| GET/POST/DELETE | `/api/topology/links` | Bearer/operator+ | Topology links |
| GET/POST/PUT/DELETE | `/api/models` | Bearer/root | AI model config |
| GET/POST | `/api/pm2/*` | Bearer/operator+ | PM2 management |
| POST | `/api/chat` | Bearer | AI assistant |
| GET | `/api/system/info` | Bearer | System info |

## Deployment

### Quick Start
```bash
# Prerequisites: Go 1.26+, Node.js 22+, PostgreSQL 15+
createdb netops

# Option A: Run from source (no compilation)
cd frontend && npm install --legacy-peer-deps && cd ..
make run           # Terminal 1: backend on :8081
make dev-frontend  # Terminal 2: frontend on :5173

# Option B: Build single binary
make build
./netops    # → http://localhost:8081 (admin / admin)
```

### Docker
```bash
make docker-build
docker run -p 8081:8081 \
  -e JWT_SECRET="secret" \
  -v ~/.openclaw:/root/.openclaw \
  netops-asset-manager:latest
```

### Configuration
`config.yaml` with env var override support (via Viper):

| Key | Default | Description |
|---|---|---|
| `PORT` | 8081 | Listen port |
| `DATABASE_URL` | postgres://... | PostgreSQL connection |
| `JWT_SECRET` | (change me) | JWT signing key |
| `JWT_EXPIRY` | 24h | Token TTL |
| `PROBE_INTERVAL` | 5m | Health probe interval |
| `SSH_CONNECT_TIMEOUT` | 10s | SSH connection timeout |

## Vendor → Driver Mapping

| Vendor | Driver | Config Command |
|---|---|---|
| H3C | hp_comware | `display current-configuration` |
| Huawei | huawei | `display current-configuration` |
| Cisco | cisco_ios | `show running-config` |
| MikroTik | mikrotik_routeros | `/export` |
| Linux | linux | `cat /etc/os-release && ip addr` |

## References
- `references/automation.md` — Automation implementation guide
- `references/vendors.md` — Vendor command reference
- `references/dependencies.md` — System dependency guide
- `references/snmp.md` — SNMP configuration reference