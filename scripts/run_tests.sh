#!/usr/bin/env bash
# Run tests through the project virtualenv.
# Usage: ./scripts/run_tests.sh [pytest args...]
#   e.g. ./scripts/run_tests.sh -q
#        ./scripts/run_tests.sh tests/test_rules.py -k test_filter
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VENV_PYTHON="$REPO_ROOT/.venv/bin/python"
VENV_PYTEST="$REPO_ROOT/.venv/bin/pytest"

if [ ! -f "$VENV_PYTHON" ]; then
  echo "⚠️  No virtualenv found. Creating one..."
  python3 -m venv .venv
fi

if [ ! -f "$VENV_PYTEST" ]; then
  echo "⚠️  Dev dependencies missing. Installing..."
  "$VENV_PYTHON" -m pip install --quiet -e '.[dev]'
fi

echo "Using: $VENV_PYTEST"
exec "$VENV_PYTEST" "${@:--q}"
