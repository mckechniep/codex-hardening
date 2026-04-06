#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
codex_dir="${HOME}/.codex"
backup_dir="${codex_dir}/backups/codex-hardening-$(date +%Y%m%d-%H%M%S)"

mkdir -p \
  "${codex_dir}/backups" \
  "${codex_dir}/hooks" \
  "${codex_dir}/policies" \
  "${codex_dir}/rules"

mkdir -p "${backup_dir}"

if [[ -f "${codex_dir}/hooks.json" ]]; then
  cp -a "${codex_dir}/hooks.json" "${backup_dir}/"
fi

if [[ -f "${codex_dir}/config.toml" ]]; then
  cp -a "${codex_dir}/config.toml" "${backup_dir}/"
fi

if [[ -d "${codex_dir}/hooks" ]]; then
  cp -a "${codex_dir}/hooks" "${backup_dir}/hooks-preinstall" 2>/dev/null || true
fi

if [[ -d "${codex_dir}/rules" ]]; then
  cp -a "${codex_dir}/rules" "${backup_dir}/rules-preinstall" 2>/dev/null || true
fi

if [[ -d "${codex_dir}/policies" ]]; then
  cp -a "${codex_dir}/policies" "${backup_dir}/policies-preinstall" 2>/dev/null || true
fi

install -m 0644 "${repo_dir}/rules/default.rules" "${codex_dir}/rules/default.rules"
install -m 0644 "${repo_dir}/policies/network_allowlist.json" "${codex_dir}/policies/network_allowlist.json"
install -m 0644 "${repo_dir}/hooks/block_destructive.py" "${codex_dir}/hooks/block_destructive.py"
install -m 0644 "${repo_dir}/hooks/block_network_egress.py" "${codex_dir}/hooks/block_network_egress.py"

sed "s|__HOME__|${HOME}|g" "${repo_dir}/templates/hooks.json.template" > "${codex_dir}/hooks.json"

cat <<EOF
Installed Codex hardening assets into ${codex_dir}
Backup created at ${backup_dir}

Next steps:
1. Merge ${repo_dir}/templates/config-hardening-snippet.toml into ${codex_dir}/config.toml
2. Review ${codex_dir}/policies/network_allowlist.json
3. Restart Codex
EOF
