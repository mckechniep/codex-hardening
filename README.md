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

## Beginner-Friendly Mental Model

This repo is not a Codex plugin. It is a local Codex hardening bundle.

It installs a small set of files under `~/.codex/`:

- Codex config defaults
- Codex `PreToolUse` hooks
- Codex execpolicy rules
- a `codex-net` helper script
- network profile policy

The goal is to make Codex behave like this:

1. Ordinary coding commands still work.
2. Obviously destructive shell commands are blocked before they run.
3. Network use must be explicit instead of silent.
4. Network commands are grouped into named profiles such as `dev_local`, `registries`, `git_readonly`, or `relaxed_network`.
5. Stronger WSL network isolation can be enabled later, but the default path stays lightweight.

## What This Bundle Does Now

After install, the bundle:

- backs up the current `~/.codex` config, hooks, rules, policies, instructions, and scripts
- installs Codex `PreToolUse` hooks for destructive-command and network-egress checks
- installs native execpolicy rules for coarse manual-only operations
- merges hardening defaults into `~/.codex/config.toml`
- merges shipped network profiles into `~/.codex/policies/network_profiles.toml`
- appends managed developer instructions that nudge Codex toward `codex-net autoexec -- ...` for likely network commands
- installs `~/.codex/scripts/codex-net` for profile-based network execution

The default backend is `hook_only`. It is an intent and command-validation layer, not packet isolation. The stronger `linux_wsl_netns` backend can be enabled explicitly on capable WSL hosts and runs wrapped commands through a transient network namespace with nftables rules.

## How A Command Flows

When Codex tries to run a shell command, the flow is:

```text
Codex proposes a shell command
  -> Codex sandbox applies filesystem/network limits
  -> PreToolUse hooks inspect the command text
  -> destructive commands are blocked
  -> direct network commands are blocked or validated
  -> allowed commands run
```

The sandbox and hooks solve different problems.

The sandbox is Codex's built-in guardrail around commands Codex runs. With this repo's default config, Codex uses `workspace-write` and shell network access is disabled by default. That is not a virtual machine, but it does limit Codex-run commands from writing freely across the host or using ambient network access.

The hooks are extra checks before a shell command runs. They look for things like `git reset --hard`, `rm -rf /`, `curl https://...`, `npm install`, or `git pull origin main`.

## What Is A Wrapped Command?

A wrapped command is a normal command run through `codex-net`.

Direct command:

```bash
curl https://github.com
```

Wrapped command:

```bash
~/.codex/scripts/codex-net exec --profile registries -- curl https://github.com
```

The wrapper gives the policy layer an explicit statement:

```text
profile: registries
real command: curl https://github.com
```

That lets `codex-net` check the selected profile before running the real command. In the default `hook_only` backend, this is literal command validation and intent tracking: profile-wrapped commands must expose an inspected network destination in the command text. In stronger backends like `linux_wsl_netns`, the wrapper is also where the per-command network namespace and firewall rules are attached, so arbitrary wrapped commands can be constrained by packet policy instead of command-string inspection alone.

`autoexec` can choose a profile for common commands:

```bash
~/.codex/scripts/codex-net autoexec -- npm update
~/.codex/scripts/codex-net autoexec -- git pull origin main
```

## Network Profiles

Profiles live in `~/.codex/policies/network_profiles.toml` after install. The repo copy is [policies/network_profiles.toml](./policies/network_profiles.toml).

Profiles do not inherit from each other. If two profiles allow the same host, that is duplication, not inheritance.

The host recommendation from `codex-net setup` is automatic. Users do not configure a special "recommended" profile. The setup menu checks the current machine:

- if WSL namespace prerequisites are ready, option `1` recommends `linux_wsl_netns`
- otherwise, option `1` recommends `hook_only`

The setup menu now asks whether to make the selected backend the default for future Codex sessions. Users can also do it directly:

```bash
~/.codex/scripts/codex-net make-default hook_only
```

or, on a WSL host where strict mode is ready:

```bash
~/.codex/scripts/codex-net make-default netns --prepare --sudo
```

The guided picker still supports temporary trial mode. Use option `4` in `codex-net setup` to clear a temporary override and return to the configured default.

Built-in profiles:

- `offline`: no remote network access.
- `dev_local`: localhost development servers such as ports `3000`, `8000`, and `8080`.
- `registries`: common package/source hosts such as GitHub, PyPI, npm, and crates.io over HTTPS.
- `git_readonly`: GitHub over SSH/HTTPS for Git remote operations.
- `relaxed_network`: intentionally broad personal-use profile that allows any remote domain on common ports.
- `custom`: empty user-managed profile.

The relaxed profile exists for convenience while you are tuning the setup:

```bash
~/.codex/scripts/codex-net exec --profile relaxed_network -- curl https://example.com
~/.codex/scripts/codex-net exec --profile relaxed_network -- ssh git@github.com
```

It is intentionally less restrictive than `registries` and `git_readonly`. Keep it if your priority is smooth day-to-day work; remove it or set `require_approval = true` if your priority is tighter network control.

## Approval Required Profiles

Profiles can contain:

```toml
require_approval = true
```

Today, this repo treats that as "do not let Codex run this automatically." Codex hooks can reliably allow or block, but the current `PreToolUse` hook path cannot reliably show a native approval prompt for this custom profile decision. So the safe behavior is to fail closed.

If you want Codex to run a profile unattended through `codex-net`, set:

```toml
require_approval = false
```

If you want human review first, leave `require_approval = true` and run the command manually after checking it.

## Allowing Sites Or Commands

Users can allow specific sites and commands in `~/.codex/policies/network_profiles.toml`.

The easy path is `codex-net approve`. Users give it a URL or Git-style host, and it infers normal ports:

- `https://...` -> HTTPS
- `http://...` -> HTTP
- `ssh://...`, `git@host:path`, `ssh`, `scp`, or `rsync` commands -> SSH

Examples:

```bash
~/.codex/scripts/codex-net approve https://api.mycompany.com --command "mycli sync"
~/.codex/scripts/codex-net approve git@github.com:example/repo.git --command "git ls-remote"
~/.codex/scripts/codex-net approve https://api.mycompany.com --tool mycli
```

That updates the `approved` profile and maps the command or tool to it. The default `approved` profile has `require_approval = false`, so matching wrapped commands can run unattended.
In `hook_only`, the command still needs the destination visible in the command text, such as `mycli sync https://api.mycompany.com` or `git ls-remote git@github.com:example/repo.git`. Implicit commands like `git fetch origin` need the stricter namespace backend or a manual run because the hook cannot see the real remote host.

Only unusual services need an explicit port:

```bash
~/.codex/scripts/codex-net approve https://internal.example.com --command "internal sync" --tcp-port 8443
```

The underlying TOML looks like this after approval:

```toml
[profiles.approved]
description = "User-approved unattended destinations and commands."
allow_localhost = false
allowed_domains = [
  "api.mycompany.com",
]
allowed_tcp_ports = [443]
allowed_udp_ports = [53]
require_approval = false

[command_profiles]
"mycli sync" = "approved"
```

Then this can run through policy:

```bash
~/.codex/scripts/codex-net autoexec -- mycli sync https://api.mycompany.com
```

With `require_approval = false`, Codex may run matching wrapped commands unattended. With `require_approval = true`, this bundle blocks Codex from running that profile automatically and expects the human to run it after review.

Advanced users can still hand-edit a custom profile:

```toml
[tool_profiles]
mycli = "custom"

[profiles.custom]
description = "My company API."
allow_localhost = false
allowed_domains = ["api.mycompany.com"]
allowed_tcp_ports = [443]
allowed_udp_ports = [53]
require_approval = false
```

For broad personal use, users can route specific commands to `relaxed_network`, which allows any remote domain on common ports:

```toml
[command_profiles]
"mycli sync" = "relaxed_network"
```

That is convenient, but less strict. The safer pattern is to add only the exact domains and ports the user trusts.

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
- `templates/model-instructions.md`
  Developer-instruction snippet that biases Codex toward `codex-net autoexec -- ...` for network-intent shell commands
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
3. Answer the guided backend setup menu.
4. Restart Codex.

`scripts/enable.sh` runs the lower-level installer, then launches `codex-net setup`, an interactive menu that detects whether the host looks like supported WSL 2, checks backend readiness, and lets the user choose light hook-only mode, stricter WSL namespace mode, or rollback/default mode.
The installer copies hooks, rules, policies, helper scripts, and a developer-instruction snippet into `~/.codex`, merges the hardening hooks into `~/.codex/hooks.json`, safely merges the hardening config into `~/.codex/config.toml`, and safely merges the shipped network policy into `~/.codex/policies/network_profiles.toml`.
The installer adds the hardening network guidance to `developer_instructions` with a managed block so Codex still keeps its built-in instruction file while preferring `codex-net autoexec -- ...` for likely networked shell commands before the hook fallback has to block them.
If an existing config or policy TOML file is malformed, install fails loudly instead of pretending the hardening was applied.

Quick install:

```bash
git clone <this-repo-url>
cd codex-hardening
scripts/enable.sh
```

To rerun the backend picker later:

```bash
~/.codex/scripts/codex-net setup
```

## Config Merge Notes

The config merge script manages these hardening settings:

- `approval_policy = "on-request"`
- `sandbox_mode = "workspace-write"`
- `web_search = "cached"`
- `[history] persistence = "none"`
- `[sandbox_workspace_write] network_access = false`
- `[features] hooks = true`
- `[shell_environment_policy] inherit = "core"`
- `[shell_environment_policy] include_only = [...]`

For those managed hardening keys, the installer follows this rule:

- missing settings are added
- known unsafe settings are repaired
- stricter safe settings are preserved
- unrelated user settings are preserved
- secret-looking environment names are pruned from `shell_environment_policy.include_only`

Examples of repaired settings:

- `approval_policy = "never"` becomes `approval_policy = "on-request"`
- `sandbox_mode = "danger-full-access"` becomes `sandbox_mode = "workspace-write"`
- `[sandbox_workspace_write] network_access = true` becomes `false`
- `[features] codex_hooks` is removed if present, and `[features] hooks = true` is added
- `[history] persistence` values other than `"none"` become `"none"`
- `[shell_environment_policy] inherit = "all"` becomes `"core"`

Examples of preserved settings:

- `sandbox_mode = "read-only"` is kept because it is stricter than the baseline
- `web_search = false` is kept because it is stricter than cached search
- `[shell_environment_policy] inherit = "none"` is kept because it is stricter than `core`
- trusted projects, plugin settings, model preferences, UI settings, and other unrelated keys are not rewritten

The installer also appends a managed block to this additive setting:

- `developer_instructions`

For `~/.codex/policies/network_profiles.toml`, the installer now also:

- adds missing top-level policy settings
- adds missing backend sections, profiles, tool mappings, and command mappings
- extends the shipped stock-profile allowlists and port lists with any newly added defaults
- leaves existing user-selected profile scalar settings unchanged

That means a user who intentionally picked `linux_wsl_netns`, changed a profile to require approval, or added custom profiles should keep that policy. The installer adds missing shipped structure around it and reports anything it skipped.

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

python3 ~/.codex/hooks/block_network_egress.py <<'EOF'
{"tool_input":{"command":"~/.codex/scripts/codex-net exec --profile dev_local -- curl http://localhost:8080"}}
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
- the default `hook_only` backend is not packet containment
- the explicit `linux_wsl_netns` backend provides first-pass packet enforcement on capable WSL hosts

What it is already good at:

- blocking obviously destructive shell commands before Codex runs them
- keeping Codex in `workspace-write` with network disabled by default
- blocking direct, explicit shell network commands unless they go through `codex-net`
- forcing network use into named profiles instead of silent ambient access
- reducing inherited shell environment so tokens and local state are exposed less broadly
- repairing known unsafe managed Codex settings during install while preserving unrelated user settings
- running wrapped commands through transient network namespaces when `linux_wsl_netns` is selected and prepared

What still has limits:

- `hook_only` cannot contain arbitrary network-capable binaries below the shell-command layer
- `hook_only` still requires literal, inspectable destinations for profile-wrapped commands
- `linux_wsl_netns` still has first-pass DNS behavior, not the planned local policy DNS stub
- `linux_wsl_nft` remains kernel-conditional and depends on `CONFIG_NFT_SOCKET`

If you want a stronger stock-WSL-compatible backend, see [docs/stock-wsl-backend-options.md](./docs/stock-wsl-backend-options.md).

## Roadmap

The next hardening steps are tracked in [docs/hardening-roadmap.md](./docs/hardening-roadmap.md).
The stock-WSL backend replacement options are compared in [docs/stock-wsl-backend-options.md](./docs/stock-wsl-backend-options.md).
The concrete namespace-backend implementation plan lives in [docs/namespace-backend-plan.md](./docs/namespace-backend-plan.md).

## WSL Backend

This repo now uses profile-based network policy only. The legacy JSON allowlist fallback has been removed.

This repo includes a WSL-first network-enforcement backend that keeps Codex offline by default but allows wrapped, profile-based network access with real Linux-side egress controls.

See [docs/wsl-first-architecture.md](./docs/wsl-first-architecture.md) for the architecture and [templates/network-profiles.template.toml](./templates/network-profiles.template.toml) for the policy shape.

Supported default today:

- `hook_only` is the supported backend on stock WSL and remains the default shipped policy
- `linux_wsl_nft` is kernel-dependent and should be treated as conditional, not baseline
- a WSL 2 setup that boots a custom kernel through `.wslconfig` can still be a valid `linux_wsl_nft` target if that kernel enables the required nft socket support and passes `codex-net doctor`
- `linux_wsl_netns` has a first-pass real execution path for stock WSL and is the stronger optional path when `codex-net doctor` says it is ready

Today, the workflow is:

- direct shell network commands are blocked when a network profile config is present
- profile-wrapped commands must go through `codex-net exec --profile ... -- ...`
- `codex-net autoexec -- ...` can now choose the mapped profile automatically for common commands such as `git fetch origin`, `git pull origin main`, `npm ci`, `npm update`, or `curl https://github.com`
- the installed developer instructions now bias Codex toward emitting `codex-net autoexec -- ...` directly for likely network-intent shell commands
- the wrapper validates the selected profile before launching the command
- in `hook_only`, wrapped commands must expose a literal destination the policy can inspect; arbitrary profile-wrapped binaries require `linux_wsl_netns`, `linux_wsl_nft`, or manual execution
- profiles marked `require_approval = true` are denied in the hook/wrapper execution path because Codex `PreToolUse` hooks cannot currently produce a native approval prompt; run those commands manually after review, or set `require_approval = false` for profiles you intentionally allow unattended
- `codex-net setup` provides the guided backend picker used by `scripts/enable.sh`; it recommends hook-only mode on non-WSL or unready hosts and offers WSL namespace isolation when prerequisites are present
- `codex-net make-default <mode>` saves a backend as the configured default without hand-editing `network_profiles.toml`
- `codex-net approve <url-or-host> --command "..."` adds a trusted site and command mapping without requiring users to know normal ports
- `codex-net backend-info` explains the available backends, their readiness, and the current effective selection
- `codex-net use hook_only`, `codex-net use netns --prepare --sudo`, and `codex-net use default --teardown --sudo` remain the lower-level temporary choose / enable / rollback commands used by the guided setup flow
- `codex-net backend-set <backend>` enables a backend temporarily through an override file instead of permanently editing the user's policy
- `codex-net backend-set <backend> --persist` writes the backend into `network_profiles.toml` when the user explicitly wants that
- `codex-net backend-clear` removes the temporary override and returns to the configured backend from `network_profiles.toml`
- `codex-net doctor` checks whether the WSL nftables backend prerequisites are present
- `codex-net compile-profiles` resolves domains and renders nftables-friendly set files for the next backend step
- `codex-net apply-rules --sudo` prepares the profile slices, validates, replaces, and applies the generated nftables table for the configured backend
- `codex-net backend-status` checks whether the recorded backend state still matches the compiled artifacts on disk
- `codex-net remove-rules --sudo` removes the installed nftables table and the prepared slice units cleanly
- `codex-net exec` launches wrapped commands through a profile scope inside a persistent per-profile slice
- `codex-net doctor --json` reports readiness for both `linux_wsl_nft` and `linux_wsl_netns`
- `codex-net netns-spike --sudo -- <command>` performs the experimental Phase 5A namespace create/run/cleanup check on stock WSL
- when `backend = "linux_wsl_netns"`, `codex-net apply-rules --sudo` installs base runtime nftables scaffolding plus local backend state, `codex-net backend-status` reports whether that base runtime still matches disk state and whether any execution records are active, and `codex-net exec --profile ... -- ...` creates a per-execution namespace, installs namespace-local name resolution assets, applies a per-execution nftables table, and then runs the wrapped command as the original user

If `codex-net doctor` reports `nft_socket_expr: ok`, advanced users can try the kernel-dependent WSL nftables backend without manually editing policy files:

```bash
~/.codex/scripts/codex-net doctor
~/.codex/scripts/codex-net make-default nft --prepare --sudo
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
- build a namespace-local `hosts` file for explicit profile domains
- install a dead-end `resolv.conf` for explicit domain profiles, or host resolver config for wildcard profiles such as `relaxed_network`
- create a per-execution namespace and veth pair
- apply a per-execution nftables table keyed to that namespace interface and subnet
- run the wrapped command as the original user inside the namespace
- remove the per-execution table, namespace assets, and execution record on exit

Current caveat for that backend:

- explicit `localhost` targets are rejected, because namespace loopback is not host loopback yet
- if you need a host-local service, wrap the command through a shell and use `$CODEX_NET_HOST_GATEWAY`, for example `codex-net exec --profile dev_local -- sh -lc 'curl http://$CODEX_NET_HOST_GATEWAY:3000'`
- allowed hostnames currently resolve through the generated `hosts` file, so the backend fails closed if a profile domain cannot be resolved before launch
- wildcard profiles such as `relaxed_network` allow any remote address on the profile's allowed ports and use the host resolver config instead of the generated `hosts` file

Beginner-friendly backend selection flow:

```bash
scripts/enable.sh
~/.codex/scripts/codex-net setup
~/.codex/scripts/codex-net approve https://api.mycompany.com --command "mycli sync"
~/.codex/scripts/codex-net autoexec -- mycli sync https://api.mycompany.com
```

That sequence:

- explains the backends and readiness
- asks the user how strict they want the network controls to be
- recommends the portable hook-only backend unless WSL namespace isolation is ready
- prepares WSL namespace runtime state when the user picks strict mode
- adds a trusted site and command mapping without hand-editing policy files
- runs a networked command with automatic profile selection

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
- the first-pass `linux_wsl_netns` backend currently uses generated `hosts` files for explicit domain profiles and the host resolver config for wildcard profiles instead of a local policy DNS stub
- The network hook only sees literal command text.
- Dynamic destinations like `$URL` are blocked because they cannot be verified safely.
- This protects Codex-driven shell actions, not commands a human runs directly.
