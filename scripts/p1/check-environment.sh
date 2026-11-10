#!/usr/bin/env bash
set -euo pipefail
umask 077
p1_script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
command -v python3 >/dev/null 2>&1 || {
  printf '%s\n' 'STOP: python3 is required' >&2
  exit 2
}
exec python3 "${p1_script_dir}/env_probe.py" "$@"
