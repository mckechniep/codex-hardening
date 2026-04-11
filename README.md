# Codex Hardening

Shareable local hardening for Codex CLI.

This repo packages a practical baseline for developers who want:

- sandboxed default execution
- approval-gated risky actions
- a coarse deny/prompt rule layer
- a destructive-command pre-execution hook
- a profile-based network egress hook
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
  Blocks outbound shell network usage unless it matches a configured network profile
- `policies/network_profiles.toml`
  Profile-based network policy used by `codex-net`
- `scripts/enable.sh`
  Guided first-run entrypoint that installs the assets and then prints backend choices
- `scripts/install.sh`
  Lower-level installer that copies the shareable assets into `~/.codex`
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
2. Run `scripts/enable.sh`.
3. Pick a backend explicitly from the commands it prints.
4. Restart Codex.

`scripts/enable.sh` runs the lower-level installer, then shows the backend chooser and the exact commands for `hook_only`, `linux_wsl_netns`, and rollback.
The installer copies hooks, rules, policies, and helper scripts into `~/.codex`, merges the hardening hooks into `~/.codex/hooks.json`, and safely merges the hardening config into `~/.codex/config.toml`: missing settings are added automatically, but conflicting existing user settings are left unchanged and reported in the install summary.

## Config Merge Notes

The config merge script manages these settings:

- `approval_policy = "on-request"`
- `sandbox_mode = "workspace-write"`
- `web_search = "cached"`
- `[history] persistence = "none"`
- `[sandbox_workspace_write] network_access = false`
- `[features] codex_hooks = true`
- `[shell_environment_policy] inherit = "core"`
- `[shell_environment_policy] include_only = [...]`

It intentionally does not force-overwrite conflicting values in an existing `config.toml` if it contains:

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
python3 -m unittest -v

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

## Practical Value Today

Blunt version:

- this repo is useful today as a guardrail bundle
- it is not yet true network containment on stock WSL

What it is already good at:

- blocking obviously destructive shell commands before Codex runs them
- keeping Codex in `workspace-write` with network disabled by default
- blocking direct, explicit shell network commands unless they go through `codex-net`
- forcing network use into named profiles instead of silent ambient access
- reducing inherited shell environment so tokens and local state are exposed less broadly

What it is not yet good at on stock WSL:

- reliably containing arbitrary network-capable binaries below the shell-command layer
- proving that implicit commands like `git fetch origin` or `npm install` can only reach approved destinations without a human decision
- delivering strong Linux-side packet enforcement on the default Microsoft WSL kernel

If you want a stronger stock-WSL-compatible backend, see [docs/stock-wsl-backend-options.md](./docs/stock-wsl-backend-options.md).

## Roadmap

The next hardening steps are tracked in [docs/hardening-roadmap.md](./docs/hardening-roadmap.md).
The stock-WSL backend replacement options are compared in [docs/stock-wsl-backend-options.md](./docs/stock-wsl-backend-options.md).
The concrete namespace-backend implementation plan lives in [docs/namespace-backend-plan.md](./docs/namespace-backend-plan.md).

## WSL Backend

This repo now uses profile-based network policy only. The legacy JSON allowlist fallback has been removed.

This repo includes a WSL-first network-enforcement backend that keeps Codex offline by default but allows wrapped, profile-based network access with real Linux-side egress controls.

See [docs/wsl-first-architecture.md](./docs/wsl-first-architecture.md) for the architecture and [templates/network-profiles.template.toml](./templates/network-profiles.template.toml) for the planned policy shape.

Supported default today:

- `hook_only` is the supported backend on stock WSL and remains the default shipped policy
- `linux_wsl_nft` is kernel-dependent and should be treated as conditional, not baseline
- if you are on the stock Microsoft WSL kernel, expect to stay on `hook_only` unless you intentionally move to a kernel that enables the required nft socket support
- a WSL 2 setup that boots a custom kernel through `.wslconfig` can still be a valid `linux_wsl_nft` target if that kernel enables the required nft socket support and passes `codex-net doctor`
- `linux_wsl_netns` now has a first-pass real execution path for stock WSL, but it is still an advanced path rather than the default install recommendation

Today, the workflow is:

- direct shell network commands are blocked when a network profile config is present
- wrapped commands must go through `codex-net exec --profile ... -- ...`
- `codex-net autoexec -- ...` can now choose the mapped profile automatically for common commands such as `git fetch origin`, `npm ci`, or `curl https://github.com`
- the wrapper validates the selected profile before launching the command
- `codex-net backend-info` explains the available backends, their readiness, and the current effective selection
- `codex-net use hook_only`, `codex-net use netns --prepare --sudo`, and `codex-net use default --teardown --sudo` cover the common choose / enable / rollback flow
- `codex-net backend-set <backend>` enables a backend temporarily through an override file instead of permanently editing the user's policy
- `codex-net backend-set <backend> --persist` writes the backend into `network_profiles.toml` when the user explicitly wants that
- `codex-net backend-clear` removes the temporary override and returns to the configured backend from `network_profiles.toml`
- `codex-net doctor` checks whether the WSL nftables backend prerequisites are present
- `codex-net compile-profiles` resolves domains and renders nftables-friendly set files for the next backend step
- `codex-net apply-rules --sudo` prepares the profile slices, validates, replaces, and applies the generated nftables table for the configured backend
- `codex-net backend-status` checks whether the recorded backend state still matches the compiled artifacts on disk
- `codex-net remove-rules --sudo` removes the installed nftables table and the prepared slice units cleanly
- `codex-net exec` launches wrapped commands through a profile scope inside a persistent per-profile slice
- `codex-net doctor --json` now reports readiness for both `linux_wsl_nft` and the planned `linux_wsl_netns` backend
- `codex-net netns-spike --sudo -- <command>` performs the experimental Phase 5A namespace create/run/cleanup check on stock WSL
- when `backend = "linux_wsl_netns"`, `codex-net apply-rules --sudo` installs base runtime nftables scaffolding plus local backend state, `codex-net backend-status` reports whether that base runtime still matches disk state and whether any execution records are active, and `codex-net exec --profile ... -- ...` now creates a per-execution namespace, installs a namespace-local `hosts` file plus fail-closed `resolv.conf`, applies a per-execution nftables table, and then runs the wrapped command as the original user

If `codex-net doctor` reports `nft_socket_expr: ok`, you can try real WSL enforcement by setting `backend = "linux_wsl_nft"` in `network_profiles.toml`, then run:

```bash
~/.codex/scripts/codex-net doctor
~/.codex/scripts/codex-net apply-rules --sudo
~/.codex/scripts/codex-net backend-status
```

When that backend is active, `codex-net exec --profile ... -- ...` refuses to run if:

- no applied backend state is recorded
- the compiled nftables file on disk no longer matches the recorded state
- the configured systemd manager for the backend is not reachable for profile-bound scopes

This is no longer just compile-only scaffolding. The `linux_wsl_nft` path now owns actual nftables apply/remove lifecycle and execution preflight when the host kernel supports it.
The `hook_only` backend is the supported stock-WSL default today. It can validate commands whose actual remote targets are visible in the command text, such as `curl https://...` or `git clone https://...`. Commands like `git fetch origin`, package-manager installs against implicit registries, and custom binaries still need either the `linux_wsl_netns` backend or a manual decision.
When `backend = "linux_wsl_nft"` is enabled, the execution path is: compile profiles, prepare per-profile slice units, apply the generated nftables rules, then launch wrapped commands through `systemd-run ... --scope --slice=<profile-slice>` via `codex-net exec`.

When `backend = "linux_wsl_netns"` is enabled, the first-pass execution path is:

- require applied base runtime state from `codex-net apply-rules --sudo`
- resolve the selected profile's allowed domains to current IPv4 answers
- build a namespace-local `hosts` file for those domains and a dead-end `resolv.conf`
- create a per-execution namespace and veth pair
- apply a per-execution nftables table keyed to that namespace interface and subnet
- run the wrapped command as the original user inside the namespace
- remove the per-execution table, namespace assets, and execution record on exit

Current caveat for that backend:

- explicit `localhost` targets are rejected, because namespace loopback is not host loopback yet
- if you need a host-local service, wrap the command through a shell and use `$CODEX_NET_HOST_GATEWAY`, for example `codex-net exec --profile dev_local -- sh -lc 'curl http://$CODEX_NET_HOST_GATEWAY:3000'`
- allowed hostnames currently resolve through the generated `hosts` file, so the backend fails closed if a profile domain cannot be resolved before launch

Beginner-friendly backend selection flow:

```bash
scripts/enable.sh
~/.codex/scripts/codex-net use hook_only
~/.codex/scripts/codex-net use netns --prepare --sudo
~/.codex/scripts/codex-net autoexec -- git fetch origin
~/.codex/scripts/codex-net use default --teardown --sudo
```

That sequence:

- explains the backends and readiness
- enables `linux_wsl_netns` temporarily without permanently editing the user's policy file
- prepares its runtime state
- runs a networked command with automatic profile selection
- tears it down and returns to the configured default backend

Important kernel requirement:

- the `linux_wsl_nft` backend requires kernel support for the nft socket expression via `CONFIG_NFT_SOCKET`
- on the Microsoft WSL kernel `6.6.87.2-microsoft-standard-WSL2` validated on April 9, 2026, `CONFIG_NFT_SOCKET` was not set
- on kernels like that, `codex-net doctor` should report `nft_socket_expr: missing` and `codex-net apply-rules` will now fail immediately with an explicit capability error instead of a long nft validation dump
- on those kernels, stay on `hook_only`; do not treat `linux_wsl_nft` as part of the default install path

Phase 5A validation command:

```bash
~/.codex/scripts/codex-net doctor --json
~/.codex/scripts/codex-net netns-spike --sudo -- sh -lc 'id -u; ip route'
```

Expected shape:

- `backend_readiness.linux_wsl_nft` may still be `false` on stock WSL
- `backend_readiness.linux_wsl_netns` should be `true` on a stock-WSL-capable host
- the spike command should create a temporary namespace, run as your normal user, print a default route inside that namespace, and then clean itself up

Phase 5B validation flow:

```bash
cp policies/network_profiles.toml .tmp/netns-policy.toml
$EDITOR .tmp/netns-policy.toml   # set backend = "linux_wsl_netns"
CODEX_NET_POLICY_PATH="$PWD/.tmp/netns-policy.toml" ./scripts/codex-net apply-rules --sudo
CODEX_NET_POLICY_PATH="$PWD/.tmp/netns-policy.toml" ./scripts/codex-net backend-status --json
CODEX_NET_POLICY_PATH="$PWD/.tmp/netns-policy.toml" ./scripts/codex-net remove-rules --sudo
```

Expected shape:

- `apply-rules` reports `table_name`, `base_nft_path`, and `base_nft_sha256`
- `backend-status` reports `ready: true` and `active_exec_count: 0`
- `remove-rules` removes the base runtime table cleanly as long as no execution records exist

Phase 5C validation flow:

```bash
cp policies/network_profiles.toml .tmp/netns-policy.toml
$EDITOR .tmp/netns-policy.toml   # set backend = "linux_wsl_netns"
CODEX_NET_POLICY_PATH="$PWD/.tmp/netns-policy.toml" ./scripts/codex-net apply-rules --sudo
CODEX_NET_POLICY_PATH="$PWD/.tmp/netns-policy.toml" ./scripts/codex-net exec --profile registries -- curl https://github.com
CODEX_NET_POLICY_PATH="$PWD/.tmp/netns-policy.toml" ./scripts/codex-net backend-status --json
CODEX_NET_POLICY_PATH="$PWD/.tmp/netns-policy.toml" ./scripts/codex-net remove-rules --sudo
```

Expected shape:

- `exec` runs through a transient namespace and exits with the wrapped command's exit code
- `backend-status` returns `active_exec_count: 0` after the command exits cleanly
- commands that target `localhost` fail fast with guidance to use `$CODEX_NET_HOST_GATEWAY`

## Limitations

- Command-string inspection is not a full shell parser.
- Aliases, nested shell tricks, and indirect execution can evade simple matching.
- the first-pass `linux_wsl_netns` backend currently uses generated `hosts` files instead of a local policy DNS stub
- The network hook only sees literal command text.
- Dynamic destinations like `$URL` are blocked because they cannot be verified safely.
- This protects Codex-driven shell actions, not commands a human runs directly.
