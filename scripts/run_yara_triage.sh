#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RULESET=${TRASHCAN_BUNDLED_YARA_RULESET:-"${SCRIPT_DIR}/../rules/yara/trashcan_static_triage.yar"}

usage() {
  echo "Usage: $0 <path-to-scan> [additional-yara-args...]" >&2
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

TARGET=$1
shift || true

if ! command -v yara >/dev/null 2>&1; then
  echo "yara binary not found in PATH" >&2
  exit 1
fi

if [[ ! -f "${RULESET}" ]]; then
  echo "ruleset not found: ${RULESET}" >&2
  exit 1
fi

if [[ ! -e "${TARGET}" ]]; then
  echo "target not found: ${TARGET}" >&2
  exit 1
fi

yara -r "${RULESET}" "${TARGET}" "$@"
