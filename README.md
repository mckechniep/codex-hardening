# Codex Hardening

Shareable local hardening for Codex CLI.

This repo packages a practical baseline for developers who want:

- sandboxed default execution
- approval-gated risky actions
- a coarse deny/prompt rule layer
- a destructive-command pre-execution hook
- a network egress allowlist hook
- a reduced shell environment for subprocesses

## Orientation

This is a Codex-oriented hardening repo.

It is designed for Codex CLI configuration under `~/.codex/`, with Codex-native concepts such as:

- `config.toml`
- `rules/*.rules`
- `hooks.json`
- `PreToolUse` Bash hooks
- `workspace-write` sandboxing
- `approval_policy`

It is not a Claude config repo and does not target `~/.claude/`.

## Attribution

Credit to [AgentShield](https://github.com/affaan-m/agentshield), an AI agent security scanner focused on Claude-oriented setups.

AgentShield helped shape the audit mindset behind this repo: scan the agent surface, separate real runtime risk from noise, and then harden the active configuration with a small set of concrete controls. This repo applies that mindset to Codex specifically, using Codex-native config layers and hook points rather than Claude-specific ones.

## What This Repo Contains

- `templates/config-hardening-snippet.toml`
  Merge-safe settings to add to `~/.codex/config.toml`
- `templates/hooks.json.template`
  Hook registration with a `__HOME__` placeholder
- `rules/default.rules`
  Native Codex execpolicy rules
- `hooks/block_destructive.py`
  Blocks obviously destructive commands and manual-only operations
- `hooks/block_network_egress.py`
  Blocks outbound shell network usage unless the target is on the allowlist
- `policies/network_allowlist.json`
  Editable list of approved domains
- `policies/network_profiles.toml`
  Profile-based network policy used by `codex-net`
- `scripts/install.sh`
  Copies the shareable assets into `~/.codex`
- `scripts/codex-net`
  Wrapper entrypoint for profile-based network execution, installed to `~/.codex/scripts/codex-net`
- `scripts/codex_net_wsl.py`
  WSL backend preparation logic for readiness checks and profile compilation
- `SECURITY-RATIONALE.md`
  Why these controls exist, what they are intended to reduce, and what they do not cover

## Important Scope

This repo is for local Codex hardening under `~/.codex/`.

It does not:

- configure `/etc/codex/`
- apply org-managed policy
- sync automatically across machines
- include any personal Codex history, auth, or local project trust data

## About `~/.codex/history.jsonl`

Your Codex history file does not get pushed to GitHub as part of ordinary project repos.

Why:

- it lives under `~/.codex/`, not inside your project directory
- `git add .` only stages files inside the repo you are standing in

It would only be pushed if someone deliberately:

- created a git repo around `~/.codex/`, or
- copied `history.jsonl` into another tracked repo

This repo intentionally does not include any real `history.jsonl`, `auth.json`, or other local state.

## Recommended Install Flow

1. Clone this repo.
2. Run `scripts/install.sh`.
3. Open `~/.codex/config.toml`.
4. Merge in the settings from `templates/config-hardening-snippet.toml`.
5. Restart Codex.

The install script copies hooks, rules, policies, and helper scripts into `~/.codex`, and merges the hardening hooks into `~/.codex/hooks.json`.
It does not overwrite the full `~/.codex/config.toml`, because most developers already have model, plugin, and trusted-project settings there.

## Manual Merge Notes

Merge the following concepts into `~/.codex/config.toml`:

- `approval_policy = "on-request"`
- `sandbox_mode = "workspace-write"`
- `web_search = "cached"`
- `[history] persistence = "none"`
- `[sandbox_workspace_write] network_access = false`
- `[features] codex_hooks = true`
- `[shell_environment_policy] inherit = "core"`
- `[shell_environment_policy] include_only = [...]`

Do not blindly replace an existing `config.toml` if it contains:

- trusted project entries
- plugin settings
- model preferences
- UI settings

## Testing

Native rules:

```bash
codex execpolicy check --rules ~/.codex/rules/default.rules git reset --hard HEAD~1
codex execpolicy check --rules ~/.codex/rules/default.rules git push origin main
```

Hook tests:

```bash
python3 ~/.codex/hooks/block_destructive.py <<'EOF'
{"tool_input":{"command":"git reset --hard HEAD~1"}}
EOF

python3 ~/.codex/hooks/block_network_egress.py <<'EOF'
{"tool_input":{"command":"curl https://github.com"}}
EOF

python3 ~/.codex/hooks/block_network_egress.py <<'EOF'
{"tool_input":{"command":"curl https://evil.example"}}
EOF

python3 ~/.codex/hooks/block_network_egress.py <<'EOF'
{"tool_input":{"command":"~/.codex/scripts/codex-net exec --profile registries -- curl https://github.com"}}
EOF

~/.codex/scripts/codex-net doctor
~/.codex/scripts/codex-net compile-profiles
~/.codex/scripts/codex-net apply-rules --print-only
```

## Security Rationale

The design rationale for these controls is documented in [SECURITY-RATIONALE.md](./SECURITY-RATIONALE.md).

## WSL Backend

This repo now includes a WSL-first network-enforcement backend that keeps Codex offline by default but allows wrapped, profile-based network access with real Linux-side egress controls.

See [docs/wsl-first-architecture.md](./docs/wsl-first-architecture.md) for the architecture and [templates/network-profiles.template.toml](./templates/network-profiles.template.toml) for the planned policy shape.

Today, the workflow is:

- direct shell network commands are blocked when a network profile config is present
- wrapped commands must go through `codex-net exec --profile ... -- ...`
- the wrapper validates the selected profile before launching the command
- `codex-net doctor` checks whether the WSL nftables backend prerequisites are present
- `codex-net compile-profiles` resolves domains and renders nftables-friendly set files for the next backend step
- `codex-net apply-rules --sudo` validates, replaces, and applies the generated nftables table for the configured backend
- `codex-net backend-status` checks whether the recorded backend state still matches the compiled artifacts on disk
- `codex-net remove-rules --sudo` removes the installed nftables table cleanly
- if the WSL user systemd bus is unavailable, `codex-net exec` can fall back to `sudo systemd-run --scope ...` when `allow_system_scope_fallback = true`

To activate real WSL enforcement, set `backend = "linux_wsl_nft"` in `network_profiles.toml`, then run:

```bash
~/.codex/scripts/codex-net doctor
~/.codex/scripts/codex-net apply-rules --sudo
~/.codex/scripts/codex-net backend-status
```

When that backend is active, `codex-net exec --profile ... -- ...` refuses to run if:

- no applied backend state is recorded
- the compiled nftables file on disk no longer matches the recorded state
- neither the WSL user systemd manager nor the optional system-scope fallback is reachable for profile-bound scopes

This is no longer just compile-only scaffolding. The `linux_wsl_nft` path now owns actual nftables apply/remove lifecycle and execution preflight.
The `hook_only` backend can only validate commands whose actual remote targets are visible in the command text, such as `curl https://...` or `git clone https://...`. Commands like `git fetch origin`, package-manager installs against implicit registries, and custom binaries still need a manual decision or the future Linux backend.
When `backend = "linux_wsl_nft"` is enabled, the execution path is: compile profiles, apply the generated nftables rules, then launch wrapped commands through a profile-specific `systemd-run ... --scope` via `codex-net exec`.

## Limitations

- Command-string inspection is not a full shell parser.
- Aliases, nested shell tricks, and indirect execution can evade simple matching.
- The network hook only sees literal command text.
- Dynamic destinations like `$URL` are blocked because they cannot be verified safely.
- This protects Codex-driven shell actions, not commands a human runs directly.
