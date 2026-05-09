#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
codex_dir="${HOME}/.codex"

"${repo_dir}/scripts/install.sh"

if [[ -t 0 && -t 1 ]]; then
  cat <<EOF

Backend setup:
EOF
  "${codex_dir}/scripts/codex-net" setup
else
  cat <<EOF

Backend setup menu preview:
EOF
  "${codex_dir}/scripts/codex-net" setup --print-only
fi

cat <<EOF

After restart, the added developer instructions will make Codex prefer:
  ${codex_dir}/scripts/codex-net autoexec -- <command>
for likely network shell commands.

When a network command is blocked, retry it with:
  ${codex_dir}/scripts/codex-net autoexec -- <command>

To approve a site and command without hand-editing policy files:
  ${codex_dir}/scripts/codex-net approve https://api.example.com --command "mycli sync"

Restart Codex after setup.
EOF
