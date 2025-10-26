#!/usr/bin/env bash
# Common helpers for repository task scripts.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PROJECT_ROOT

function _log() {
  echo "[scripts] $*" >&2
}

function ensure_venv() {
  if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    return
  fi

  local venv_dir="${PROJECT_ROOT}/.venv"
  if [[ -d "${venv_dir}" ]]; then
    # shellcheck disable=SC1091
    source "${venv_dir}/bin/activate"
  fi
}

function ensure_python() {
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="${PYTHON_BIN:-$(command -v python)}"
  else
    _log "Python interpreter not found."
    exit 1
  fi
}

function run_python() {
  ensure_python
  ensure_venv
  "${PYTHON_BIN}" "$@"
}

function run_cmd() {
  ensure_venv
  "$@"
}

function check_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    _log "Required command '$1' not found on PATH"
    exit 1
  fi
}

function has_npm_script() {
  local script_name="$1"
  if [[ ! -f "${PROJECT_ROOT}/package.json" ]]; then
    return 1
  fi

  node -e "const fs=require('fs');const pkg=JSON.parse(fs.readFileSync('${PROJECT_ROOT}/package.json','utf8'));process.exit(pkg.scripts && pkg.scripts['${script_name}'] ? 0 : 1);" >/dev/null 2>&1
}
