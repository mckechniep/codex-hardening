#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
codex_dir="${HOME}/.codex"
backup_dir="${codex_dir}/backups/codex-hardening-$(date +%Y%m%d-%H%M%S)"

mkdir -p \
  "${codex_dir}/backups" \
  "${codex_dir}/hooks" \
  "${codex_dir}/instructions" \
  "${codex_dir}/policies" \
  "${codex_dir}/rules" \
  "${codex_dir}/scripts"

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

if [[ -d "${codex_dir}/instructions" ]]; then
  cp -a "${codex_dir}/instructions" "${backup_dir}/instructions-preinstall" 2>/dev/null || true
fi

if [[ -d "${codex_dir}/scripts" ]]; then
  cp -a "${codex_dir}/scripts" "${backup_dir}/scripts-preinstall" 2>/dev/null || true
fi

install -m 0644 "${repo_dir}/rules/default.rules" "${codex_dir}/rules/default.rules"
install -m 0644 "${repo_dir}/hooks/block_destructive.py" "${codex_dir}/hooks/block_destructive.py"
install -m 0644 "${repo_dir}/hooks/block_network_egress.py" "${codex_dir}/hooks/block_network_egress.py"
install -m 0644 "${repo_dir}/templates/model-instructions.md" "${codex_dir}/instructions/codex-hardening-model-instructions.md"
install -m 0644 "${repo_dir}/scripts/codex_net_policy.py" "${codex_dir}/scripts/codex_net_policy.py"
install -m 0644 "${repo_dir}/scripts/codex_net_netns.py" "${codex_dir}/scripts/codex_net_netns.py"
install -m 0644 "${repo_dir}/scripts/codex_net_wsl.py" "${codex_dir}/scripts/codex_net_wsl.py"
install -m 0755 "${repo_dir}/scripts/merge_config.py" "${codex_dir}/scripts/merge_config.py"
install -m 0755 "${repo_dir}/scripts/merge_network_profiles.py" "${codex_dir}/scripts/merge_network_profiles.py"
install -m 0755 "${repo_dir}/scripts/merge_developer_instructions.py" "${codex_dir}/scripts/merge_developer_instructions.py"
install -m 0755 "${repo_dir}/scripts/codex_net_backend.py" "${codex_dir}/scripts/codex_net_backend.py"
install -m 0755 "${repo_dir}/scripts/codex-net" "${codex_dir}/scripts/codex-net"

python3 "${repo_dir}/scripts/merge_hooks.py" \
  "${repo_dir}/templates/hooks.json.template" \
  "${codex_dir}/hooks.json"

network_policy_merge_output="$("${codex_dir}/scripts/merge_network_profiles.py" "${repo_dir}/policies/network_profiles.toml" "${codex_dir}/policies/network_profiles.toml")"
config_merge_output="$("${codex_dir}/scripts/merge_config.py" "${repo_dir}/templates/config-hardening-snippet.toml" "${codex_dir}/config.toml")"
instructions_merge_output="$("${codex_dir}/scripts/merge_developer_instructions.py" "${repo_dir}/templates/model-instructions.md" "${codex_dir}/config.toml")"
if [[ -n "${instructions_merge_output}" ]]; then
  if [[ -n "${config_merge_output}" ]]; then
    config_merge_output="${config_merge_output}
${instructions_merge_output}"
  else
    config_merge_output="${instructions_merge_output}"
  fi
fi
doctor_output="$("${codex_dir}/scripts/codex-net" doctor 2>/dev/null || true)"

cat <<EOF
Installed Codex hardening assets into ${codex_dir}
Backup created at ${backup_dir}

Next steps:
1. Pick a backend with the guided setup menu:
   ${codex_dir}/scripts/codex-net setup
2. Add ${codex_dir}/scripts to your PATH if you want to call codex-net directly
3. Approve trusted sites or commands as needed:
   ${codex_dir}/scripts/codex-net approve https://api.example.com --command "mycli sync"
4. Restart Codex after you pick a backend
EOF

if [[ -n "${config_merge_output}" ]]; then
  cat <<EOF

Config merge summary:
${config_merge_output}
EOF
fi

if [[ -n "${network_policy_merge_output}" ]]; then
  cat <<EOF

Network policy merge summary:
${network_policy_merge_output}
EOF
fi

if [[ -n "${doctor_output}" ]]; then
  cat <<EOF

Current WSL backend readiness:
${doctor_output}
EOF
fi
