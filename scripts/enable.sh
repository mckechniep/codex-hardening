#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
codex_dir="${HOME}/.codex"

"${repo_dir}/scripts/install.sh"

cat <<EOF

Choose your backend:
- Light mode: blocks direct network shell commands and keeps network access explicit.
  ${codex_dir}/scripts/codex-net use hook_only
- Isolated namespace mode: stronger stock-WSL isolation for git/package-manager traffic.
  ${codex_dir}/scripts/codex-net use netns --prepare --sudo
- Roll back to whatever backend is configured in ${codex_dir}/policies/network_profiles.toml.
  ${codex_dir}/scripts/codex-net use default --teardown --sudo

Current chooser:
EOF

"${codex_dir}/scripts/codex-net" backend-info

cat <<EOF

After restart, Codex will prefer:
  ${codex_dir}/scripts/codex-net autoexec -- <command>
for likely network shell commands, unless you already use a custom model_instructions_file.

When a network command is blocked, retry it with:
  ${codex_dir}/scripts/codex-net autoexec -- <command>

Restart Codex after you pick a backend.
EOF
