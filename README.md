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
- `scripts/install.sh`
  Copies the shareable assets into `~/.codex`
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

The install script copies hooks, rules, and policy files into `~/.codex`, and writes `~/.codex/hooks.json`.
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
```

## Security Rationale

The design rationale for these controls is documented in [SECURITY-RATIONALE.md](./SECURITY-RATIONALE.md).

## Limitations

- Command-string inspection is not a full shell parser.
- Aliases, nested shell tricks, and indirect execution can evade simple matching.
- The network hook only sees literal command text.
- Dynamic destinations like `$URL` are blocked because they cannot be verified safely.
- This protects Codex-driven shell actions, not commands a human runs directly.
