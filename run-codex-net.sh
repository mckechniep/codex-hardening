#!/usr/bin/env bash
set -u

POLICY_PATH="$PWD/.tmp/netns-policy.toml"
LOG_FILE="$PWD/codex-net-run.log"

{
  echo "=== $(date) ==="
  echo "POLICY_PATH=$POLICY_PATH"
  echo

  echo ">>> apply-rules"
  CODEX_NET_POLICY_PATH="$POLICY_PATH" ./scripts/codex-net apply-rules --sudo
  echo

  echo ">>> exec --profile registries"
  CODEX_NET_POLICY_PATH="$POLICY_PATH" ./scripts/codex-net exec --profile registries -- sh -lc '
    ip route
    echo "---"
    curl -4 -I --max-time 8 https://github.com
  '
  echo

  echo ">>> backend-status --json"
  CODEX_NET_POLICY_PATH="$POLICY_PATH" ./scripts/codex-net backend-status --json
  echo

  echo ">>> remove-rules"
  CODEX_NET_POLICY_PATH="$POLICY_PATH" ./scripts/codex-net remove-rules --sudo
  echo

  echo "=== done $(date) ==="
} 2>&1 | tee "$LOG_FILE"
