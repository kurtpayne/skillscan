#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${SKILLSCAN_REPO_URL:-https://github.com/kurtpayne/skillscan.git}"
INSTALL_DIR="${HOME}/.skillscan/runtime"
BIN_DIR="${HOME}/.local/bin"

mkdir -p "${BIN_DIR}"

if [[ -d "${INSTALL_DIR}" ]]; then
  rm -rf "${INSTALL_DIR}"
fi

git clone "${REPO_URL}" "${INSTALL_DIR}"
python3 -m venv "${INSTALL_DIR}/.venv"
"${INSTALL_DIR}/.venv/bin/pip" install --upgrade pip
"${INSTALL_DIR}/.venv/bin/pip" install "${INSTALL_DIR}"
ln -sf "${INSTALL_DIR}/.venv/bin/skillscan" "${BIN_DIR}/skillscan"

echo "Installed SkillScan to ${BIN_DIR}/skillscan"
echo "Ensure ${BIN_DIR} is in your PATH"
