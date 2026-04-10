# Progress Note: 2026-04-07

## Current State

The repo now has three network-control layers:

- Codex config and execpolicy hardening
- shell-hook network detection and wrapper enforcement
- a WSL-targeted `linux_wsl_nft` backend with real nftables lifecycle commands

The backend is no longer compile-only. `codex-net` now supports:

- `doctor`
- `compile-profiles`
- `apply-rules --sudo`
- `backend-status`
- `remove-rules --sudo`
- `exec --profile ... -- ...`

## What Landed

### Hook/profile path

- direct network commands are denied when profile config is present
- wrapped commands go through `codex-net exec --profile ... -- ...`
- `hook_only` is the supported default for stock WSL today

### WSL backend lifecycle

- profile domains are compiled into nftables-friendly IP/port sets
- `apply-rules --sudo` now validates, replaces, and applies the nft table
- `remove-rules --sudo` removes that table cleanly
- backend state is written to `~/.codex/state/codex-net/backend_state.json`
- `backend-status` verifies that recorded state still matches the compiled nft file on disk

### Scope-launch logic

- preferred path is `systemd-run --user --scope --slice=<profile-slice>`
- system-scope launch remains available only when the backend is explicitly configured for it
- nftables rules now match persistent per-profile slices rather than transient scope names

## Current Limits

These were not exercised end-to-end in this sandbox:

- real `nft` application into the kernel
- real `systemd-run --scope --slice=...` launch
- real packet filtering of a wrapped process

This environment reported:

- WSL2: yes
- cgroup v2: yes
- sudo: yes
- nft: missing
- user systemd bus: unreachable
- system systemd bus: unreachable

That means the missing piece is host validation on a real WSL box, not another major code pass.

## Real Host Finding On April 9, 2026

A real WSL2 validation run on `6.6.87.2-microsoft-standard-WSL2` showed:

- profile leaf slices can be created and anchored successfully under the user systemd manager
- the referenced cgroup paths do exist while those anchor services are running
- nft rule application still cannot proceed on that kernel because `CONFIG_NFT_SOCKET` is not enabled

That means the current `linux_wsl_nft` backend is structurally correct enough to validate its cgroup assumptions, but it is not deployable on stock kernels that omit `CONFIG_NFT_SOCKET`. The repo now needs to fail early on that capability check and treat alternative kernel support or an alternate backend as follow-on work.

## Files Added Or Extended

- `scripts/codex_net_policy.py`
- `scripts/codex_net_backend.py`
- `scripts/codex_net_wsl.py`
- `scripts/codex-net`
- `policies/network_profiles.toml`
- `templates/network-profiles.template.toml`
- `tests/test_codex_net_wsl.py`
- `docs/wsl-first-architecture.md`

Also updated:

- `hooks/block_network_egress.py`
- `scripts/install.sh`
- `README.md`

## Recommended Next Step

Treat `hook_only` as the supported default on stock WSL.

That means:

1. Leave `backend = "hook_only"` in `network_profiles.toml`.
2. Keep improving the profile coverage, hook messaging, and operator UX around implicit network decisions.
3. Treat `linux_wsl_nft` as conditional and only attempt it on kernels where `codex-net doctor` reports `nft_socket_expr: ok`.

## If Picking This Up Later

If picking this up later:

- keep `hook_only` polished as the normal path
- decide whether supporting a custom WSL kernel is acceptable for advanced users
- design an alternate stock-WSL backend that does not depend on `CONFIG_NFT_SOCKET`
