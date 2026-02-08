#!/usr/bin/env bash
set -euo pipefail

KEEP_DATA="false"
if [[ "${1:-}" == "--keep-data" ]]; then
  KEEP_DATA="true"
fi

BIN_PATH="${HOME}/.local/bin/skillscan"
RUNTIME_DIR="${HOME}/.skillscan/runtime"
DATA_DIR="${HOME}/.skillscan"

rm -f "${BIN_PATH}"
rm -rf "${RUNTIME_DIR}"

if [[ "${KEEP_DATA}" == "false" ]]; then
  rm -rf "${DATA_DIR}"
fi

echo "SkillScan uninstalled. keep-data=${KEEP_DATA}"
