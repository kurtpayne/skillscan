---
name: draft-mcp-server
description: Build a complete CrunchTools MCP server from scratch — API research, scaffolding, implementation, testing, and registry publishing
argument-hint: "[service-name, e.g. mediawiki, jira, slack]"
allowed-tools: Read, Write, Edit, Bash, AskUserQuestion, Grep, Glob, WebFetch, WebSearch, EnterPlanMode, ExitPlanMode, Task, mcp__memory__memory_search, mcp__memory__memory_store, mcp__mcp-wordpress-crunchtools__wordpress_get_page, mcp__mcp-wordpress-crunchtools__wordpress_update_page, mcp__zabbix__item_create, mcp__zabbix__item_get, mcp__zabbix__trigger_create, mcp__zabbix__trigger_get, mcp__zabbix__hostgroup_get
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: crunchtools/draft-mcp-server
# corpus-url: https://github.com/crunchtools/draft-mcp-server/blob/c3f23312143f3076ac45c5a2bcfd24d3ad24505b/SKILL.md
# corpus-round: 2026-03-19
# corpus-format: markdown_fm
---

# Build a CrunchTools MCP Server

End-to-end workflow for creating a production-grade MCP server following the crunchtools architecture. The reference implementation is [mcp-gitlab](https://github.com/crunchtools/mcp-gitlab).

All servers MUST conform to:
- **Universal constitution**: [crunchtools/constitution](https://github.com/crunchtools/constitution) — license, semver, container registry, commit standards
- **MCP Server profile**: `profiles/mcp-server.md` — security model, architecture, testing, quality gates, naming, governance

## Usage

```
/draft-mcp-server mediawiki
/draft-mcp-server jira
```

---

## Phase 1: Research and Planning

### Step 1: Search Memory

Search memory for any prior context about the target service:
- `memory_search` for the service name
- `memory_search` for existing MCP servers or integrations
- `memory_search` for "mcp server architecture" to load the crunchtools patterns

### Step 2: Research the Target API

Investigate the service's API:
- What authentication model does it use? (API token, OAuth, session cookies, CSRF tokens)
- What API style? (REST, GraphQL, Action-based like MediaWiki)
- What operations are available? (CRUD on what resources?)
- What pagination model? (offset, cursor, continuation tokens)
- Are there rate limits?

Use `WebFetch` and `WebSearch` to read API documentation.

### Step 3: Design the Tool Inventory

Ask the user with `AskUserQuestion`:
- **Scope**: Comprehensive (full API coverage), read-heavy + basic editing, or minimal v0.1?
- **Authentication**: Confirm the auth model discovered in research
- **HTTP port**: Next available port for streamable-http transport (check existing ports in memory)

Design the tool list organized by category. Target 15-60 tools depending on API surface. Each tool maps to one API operation. Use this naming pattern:
- `search` / `list_*` — read collections
- `get_*` — read single resource
- `create_*` / `edit_*` — write operations
- `delete_*` / `move_*` — destructive operations

### Step 4: Plan Approval

Enter plan mode and present the full design for user approval. The plan MUST include:
- Tool inventory table (tool name, API endpoint, description)
- Authentication flow
- Environment variables
- File structure
- Any special considerations (CSRF tokens, continuation pagination, etc.)
- **External setup checklist** (see below)

#### External Setup Checklist

Include this section in every plan so the user can work on these tasks in parallel while you build:

```
## While I build, you can set up:

1. **PyPI Trusted Publishing** (required for Phase 7)
   - Go to: https://pypi.org/manage/account/publishing/
   - Add pending publisher:
     - PyPI project: mcp-<name>-crunchtools
     - Owner: crunchtools
     - Repository: mcp-<name>
     - Workflow: publish.yml
     - Environment: (leave blank)

2. **Quay.io Repository** (required for Phase 7)
   - Go to: https://quay.io/new/?namespace=crunchtools
   - Create repository: mcp-<name>
   - Visibility: public
   - Ensure robot account secrets (QUAY_USERNAME/QUAY_PASSWORD) are set
     in the GitHub org: https://github.com/organizations/crunchtools/settings/secrets/actions

3. **GHCR Package Linking** (automatic if OCI labels are correct)
   - The `org.opencontainers.image.source` label in the Containerfile auto-links GHCR packages to the repo on first push
   - If the package already exists unlinked, delete it first: `gh api --method DELETE /orgs/crunchtools/packages/container/mcp-<name>`
   - Then push again — the OCI label will auto-link and grant GITHUB_TOKEN write access
   - After linking, make the package public at: https://github.com/orgs/crunchtools/packages
```

**Do NOT proceed to Phase 2 until the user approves the plan.**

---

## Phase 2: Project Scaffolding

The project lives at `~/Projects/crunchtools/mcp-<name>/`.

### Step 1: Read Reference Implementation

Read the naming convention table from the MCP Server profile (`profiles/mcp-server.md` Section VI) and apply it. Use `mcp-gitlab` as the template repo — read each governance file from `~/Projects/crunchtools/mcp-gitlab/` and adapt.

### Step 2: Create Directory Structure

```
~/Projects/crunchtools/mcp-<name>/
├── pyproject.toml            # name, version, deps, ruff/mypy/pytest config
├── Containerfile             # Hummingbird base, OCI labels (per constitution)
├── CLAUDE.md                 # Quick start, env vars, tool listing, dev commands
├── README.md                 # Installation, usage, tool reference, MCP Registry tag
├── LICENSE                   # AGPL-3.0-or-later (copy from mcp-gitlab)
├── SECURITY.md               # Security policy (adapt from mcp-gitlab)
├── server.json               # MCP Registry metadata
├── gourmand.toml             # Copy from mcp-gitlab
├── gourmand-exceptions.toml  # Copy from mcp-gitlab
├── .pre-commit-config.yaml   # Ruff + constitution hook (copy from mcp-gitlab)
├── .gitignore                # Copy from mcp-gitlab
├── .github/
│   ├── ISSUE_TEMPLATE/       # Copy all 3 from mcp-gitlab
│   └── workflows/
│       ├── ci.yml            # Lint + mypy + pytest + constitution validation
│       ├── container.yml     # Dual push: Quay.io + GHCR (two separate jobs)
│       ├── publish.yml       # PyPI trusted publishing
│       └── security.yml      # pip-audit + Trivy + CodeQL
├── .specify/
│   ├── memory/
│   │   └── constitution.md   # Per-repo constitution (Inherits v1.0.0, Profile: MCP Server)
│   ├── specs/
│   │   └── 000-baseline/
│   │       └── spec.md       # Tool inventory and architecture
│   └── templates/            # Copy from mcp-gitlab
├── src/
│   └── mcp_<name>_crunchtools/
│       ├── __init__.py       # Entry point with argparse (stdio/sse/streamable-http)
│       ├── __main__.py       # python -m support
│       ├── server.py         # @mcp.tool() wrappers (two-layer: delegates to tools/)
│       ├── client.py         # Hardened async httpx client (per security model)
│       ├── config.py         # SecretStr config from env vars (per security model)
│       ├── errors.py         # UserError hierarchy, credential scrubbing
│       ├── models.py         # Pydantic v2 models, extra="forbid", field limits
│       └── tools/
│           ├── __init__.py   # Re-export with __all__
│           └── <category>.py # Pure async functions per resource category
└── tests/
    ├── __init__.py
    ├── conftest.py           # _reset_client_singleton, _mock_response, _patch_client
    ├── test_tools.py         # Mocked httpx tests, tool count assertion
    └── test_validation.py    # Pydantic model validation tests
```

### Step 3: Copy Reference Files

**Copy verbatim (only change the server name):**
- `.gitignore`, `LICENSE`, `.pre-commit-config.yaml`, `gourmand.toml`, `gourmand-exceptions.toml`
- `.github/ISSUE_TEMPLATE/` (all 3 files)
- `.github/workflows/` (ci.yml, publish.yml, security.yml — change project name)
- `.specify/templates/` (both templates)

**Adapt from mcp-gitlab:**
- `.github/workflows/container.yml` — two separate **jobs**: `build-and-push-quay` and `build-and-push-ghcr` with `needs:` dependency chain
- `Containerfile` — Hummingbird base, OCI labels per universal constitution Section III
- `pyproject.toml` — name, description, dependencies, entry point per MCP Server profile Section II
- `SECURITY.md` — change project references

**Write fresh (server-specific):**
- All `src/` Python source code — implement per MCP Server profile (five-layer security, two-layer tools)
- All `tests/` — mocked httpx tests per MCP Server profile Section III
- `CLAUDE.md`, `README.md`, `server.json`, `.specify/memory/constitution.md`, `.specify/specs/000-baseline/spec.md`

**Do NOT proceed to Phase 3 until all scaffolding files are created.**

---

## Phase 3: Implementation

Build the server following the MCP Server profile architecture. The profile defines what each file must contain — refer to it directly rather than re-specifying here.

### Step 1: Core Infrastructure

Build in this order: `errors.py` → `config.py` → `client.py` → `models.py`

All security requirements come from the Five-Layer Security Model (MCP Server profile Section I.1).

### Step 2: Tools

Build tools following the Two-Layer Architecture (MCP Server profile Section I.2):
- `tools/*.py` — pure async functions that call `client.py`
- `server.py` — thin `@mcp.tool()` wrappers with `_tool` suffix

### Step 3: Entry Points

- `__init__.py` — argparse for `--transport`, `--host`, `--port`
- `__main__.py` — `from . import main; main()`

**Do NOT proceed to Phase 4 until all source code compiles.**

---

## Phase 4: Tests

Build tests following the Testing Standards (MCP Server profile Section III):
- `conftest.py` with `_reset_client_singleton`, `_mock_response`, `_patch_client`
- `test_tools.py` with mocked httpx — every tool gets a test, `test_tool_count` assertion
- `test_validation.py` for Pydantic model constraints

**Do NOT proceed to Phase 5 until all tests pass.**

---

## Phase 5: Quality Gates

Run the five gates defined in the MCP Server profile (Section V), in order:

```bash
uv run ruff check src tests         # 1. Lint
uv run mypy src                     # 2. Type check
uv run pytest -v                    # 3. Tests
gourmand --full .                   # 4. AI slop detection (skip if not installed)
podman build -f Containerfile .     # 5. Container build
```

**Do NOT proceed to Phase 6 until all gates pass.**

---

## Phase 6: Git and GitHub

```bash
cd ~/Projects/crunchtools/mcp-<name>
git init && git add . && git commit -m "Initial release: mcp-<name>-crunchtools v0.1.0

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
gh repo create crunchtools/mcp-<name> --public --source=. --push
git tag v0.1.0 && git push origin v0.1.0
```

Install pre-commit hooks: `pre-commit install`

---

## Phase 7: Publish

### Step 1: Version Bump (skip for initial v0.1.0 release)

For subsequent releases, update version in all four locations:
1. `pyproject.toml` — `version = "X.Y.Z"`
2. `src/mcp_<name>_crunchtools/server.py` — `version="X.Y.Z"` in FastMCP constructor
3. `src/mcp_<name>_crunchtools/__init__.py` — `__version__ = "X.Y.Z"`
4. `server.json` — both top-level and package-level `"version"`

### Step 2: Quality Gates → Commit → Tag → Push

Run all 5 quality gates, then:
```bash
git add . && git commit -m "Release v<VERSION>

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
git tag v<VERSION> && git push && git push origin v<VERSION>
```

### Step 3: Verify PyPI

Tag push triggers GHA publish workflow. Verify:
```bash
curl -s "https://pypi.org/pypi/mcp-<name>-crunchtools/<VERSION>/json" | python3 -c "import sys,json; print(json.load(sys.stdin)['info']['version'])"
```

### Step 4: Verify Container Registries

```bash
skopeo inspect docker://quay.io/crunchtools/mcp-<name>:<VERSION>
skopeo inspect docker://ghcr.io/crunchtools/mcp-<name>:<VERSION>
```

If GHCR packages are private, tell user to make them public at `https://github.com/orgs/crunchtools/packages`.

### Step 5: Factory Watchdog Repository Monitoring

The factory watchdog (`crunchtools/factory`) monitors all CrunchTools repos in Zabbix across 5 dimensions every 15 minutes. This monitors the **code factory** — GHA status, version sync, artifact sync, constitution validation, and open issues.

#### 5a: Add to fleet-watchdog.py

Clone or pull `~/Projects/crunchtools/factory/` and edit `fleet-watchdog.py`:

1. Add `"mcp-<name>"` to the `REPOS` list (alphabetical order)
2. Add `"mcp-<name>"` to the `MCP_REPOS` list (alphabetical order)
3. Commit and push

#### 5b: Create Zabbix Trapper Items

Create trapper items on the `factory.crunchtools.com` host (hostid `10700`) for each monitoring dimension. All items are type `2` (Zabbix trapper).

**All repos get these items:**

| Item Name | Key | value_type |
|-----------|-----|------------|
| Fleet GHA mcp-\<name\> | `fleet.gha[mcp-<name>]` | 3 (unsigned int) |
| Fleet Constitution mcp-\<name\> | `fleet.constitution[mcp-<name>]` | 3 (unsigned int) |
| Fleet Constitution Violations mcp-\<name\> | `fleet.constitution.violations[mcp-<name>]` | 4 (text) |
| Fleet Issues mcp-\<name\> | `fleet.issues.open[mcp-<name>]` | 3 (unsigned int) |

**MCP repos also get these items:**

| Item Name | Key | value_type |
|-----------|-----|------------|
| Fleet Version Sync mcp-\<name\> | `fleet.version.sync[mcp-<name>]` | 3 (unsigned int) |
| Fleet Version mcp-\<name\> | `fleet.version[mcp-<name>]` | 4 (text) |
| Fleet Artifact Sync mcp-\<name\> | `fleet.artifact.sync[mcp-<name>]` | 3 (unsigned int) |

Use the `mcp__zabbix__item_create` tool. If the Zabbix MCP server is in read-only mode, tell the user to create the items manually via the Zabbix web UI.

#### 5c: Create Zabbix Triggers

Create triggers on `factory.crunchtools.com` for the new repo:

| Trigger | Expression | Priority |
|---------|-----------|----------|
| GHA failure | `last(/factory.crunchtools.com/fleet.gha[mcp-<name>])=0` | 2 (WARNING) |
| Version desync | `last(/factory.crunchtools.com/fleet.version.sync[mcp-<name>])=0` | 4 (HIGH) |
| Artifact desync | `last(/factory.crunchtools.com/fleet.artifact.sync[mcp-<name>])=0` | 2 (WARNING) |
| Constitution violation | `last(/factory.crunchtools.com/fleet.constitution[mcp-<name>])=0` | 4 (HIGH) |

All triggers should have tags: `{"tag": "service", "value": "fleet-watchdog"}` and `{"tag": "repo", "value": "mcp-<name>"}`.

#### 5d: Deploy Updated Watchdog

On Lotor, pull the updated factory container and restart:

```bash
podman pull quay.io/crunchtools/factory:latest
systemctl --user restart factory.crunchtools.com.service
```

Verify the new repo appears in the next watchdog run by checking the container logs.

#### 5e: Service Tree (Factory Dashboard)

The factory watchdog items must also appear in service-tree.php under the `factory.crunchtools.com` section. SSH to Lotor and edit `/srv/zabbix.crunchtools.com/code/service-tree.php`:

1. Add the `fleet.gha[mcp-<name>]` item to the factory GHA status display section
2. Add the `fleet.version.sync[mcp-<name>]` item to the version sync display section
3. Add the `fleet.artifact.sync[mcp-<name>]` item to the artifact sync display section
4. Add the `fleet.constitution[mcp-<name>]` item to the constitution display section
5. Add the `fleet.issues.open[mcp-<name>]` item to the issues display section
6. Verify the new repo appears under factory.crunchtools.com at `https://zabbix.crunchtools.com/service-tree.php`

### Step 6: Publish to MCP Registry

```bash
cd ~/Projects/crunchtools/mcp-<name> && mcp-publisher validate && mcp-publisher publish
```

### Step 7: Update CrunchTools Website

Update the MCP Servers page on crunchtools.com (WordPress page ID 6129) using `wordpress_get_page` and `wordpress_update_page`. Add the new server to the table in alphabetical order.

---

## Phase 8: Store in Memory

Store the build details using `memory_store`:
- Server name, version, tool count
- Architecture decisions (auth model, API style, pagination)
- Any gotchas or special handling discovered during the build

After publishing, deploy with `/deploy-mcp-server <name>`.

---

## Output Summary

```
Server:         mcp-<name>-crunchtools
Version:        0.1.0
Tools:          <count> across <categories> categories
Architecture:   v2 (per MCP Server profile)
GitHub:         https://github.com/crunchtools/mcp-<name>
PyPI:           https://pypi.org/project/mcp-<name>-crunchtools/
Quay.io:        quay.io/crunchtools/mcp-<name>:0.1.0
GHCR:           ghcr.io/crunchtools/mcp-<name>:0.1.0
MCP Registry:   io.github.crunchtools/<name>
Factory:          factory.crunchtools.com — GHA, version, artifact, constitution, issues
WordPress:      https://crunchtools.com/software/mcp-servers/

Next: /deploy-mcp-server <name>
```