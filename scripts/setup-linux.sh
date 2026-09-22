#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
offline=0
for arg in "$@"; do
  case "$arg" in --offline) offline=1 ;; *) echo "Unknown setup option: $arg" >&2; exit 2 ;; esac
done
missing=()
command -v python3 >/dev/null 2>&1 || missing+=(python3)
if ! python3 -c 'import ensurepip,venv' >/dev/null 2>&1; then missing+=(python3-venv); fi
if ! python3 -c 'import ctypes,ctypes.util; ctypes.CDLL(ctypes.util.find_library("seccomp") or "libseccomp.so.2")' >/dev/null 2>&1; then missing+=(libseccomp2); fi
if ((${#missing[@]})); then
  if ((offline)); then echo "Offline setup blocked. Missing prerequisites: ${missing[*]}" >&2; exit 2; fi
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "Install Python 3.11–3.14 with venv/ensurepip and libseccomp using your distribution's package manager, then rerun." >&2
    exit 2
  fi
  echo "Initial setup will download missing OS prerequisites: ${missing[*]}"
  if ((EUID==0)); then
    apt-get update
    apt-get install -y --no-install-recommends "${missing[@]}"
  else
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends "${missing[@]}"
  fi
fi
options=()
if ((offline)); then options+=(--offline); fi
if [[ $(uname -r) == *[Mm]icrosoft* ]]; then
  if [[ $(uname -r) != *WSL2* && $(uname -r) != *microsoft-standard* ]]; then
    echo 'WSL2 is required; WSL1 is not supported.' >&2; exit 2
  fi
  options+=(--wsl)
fi
exec python3 scripts/bootstrap.py "${options[@]}"
