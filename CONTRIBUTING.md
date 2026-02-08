# Contributing

## Setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Run tests

```bash
pytest -q
ruff check src tests
mypy src
```

## Scope expectations

- Keep scanner behavior deterministic.
- Add regression fixtures for new detection logic.
- Update docs and example outputs when command behavior changes.
