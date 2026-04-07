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
- `hook_only` still exists for machines that cannot use the WSL backend

### WSL backend lifecycle

- profile domains are compiled into nftables-friendly IP/port sets
- `apply-rules --sudo` now validates, replaces, and applies the nft table
- `remove-rules --sudo` removes that table cleanly
- backend state is written to `~/.codex/state/codex-net/backend_state.json`
- `backend-status` verifies that recorded state still matches the compiled nft file on disk

### Scope-launch logic

- preferred path is `systemd-run --user --scope`
- new fallback path exists for WSL users without a working user bus:
  `sudo systemd-run --scope`
- the fallback is controlled by:
  `backend_linux_wsl_nft.allow_system_scope_fallback = true`

## Current Limits

These were not exercised end-to-end in this sandbox:

- real `nft` application into the kernel
- real `sudo systemd-run --scope ...` launch
- real packet filtering of a wrapped process

This environment reported:

- WSL2: yes
- cgroup v2: yes
- sudo: yes
- nft: missing
- user systemd bus: unreachable
- system systemd bus: unreachable

That means the missing piece is host validation on a real WSL box, not another major code pass.

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

Run the backend on a real WSL distro that has:

- `nftables` installed
- `sudo`
- systemd enabled if possible

Then validate this exact flow:

1. Set `backend = "linux_wsl_nft"` in `~/.codex/policies/network_profiles.toml`.
2. Run `~/.codex/scripts/codex-net doctor`.
3. Run `~/.codex/scripts/codex-net apply-rules --sudo`.
4. Run `~/.codex/scripts/codex-net backend-status`.
5. Test a permitted wrapped command.
6. Test a denied wrapped command.
7. If user-scope fails, verify the system-scope fallback path.

## If Picking This Up Later

If the real-machine validation works:

- keep this backend as the default WSL recommendation
- improve `doctor` with distro-specific install hints for `nftables`
- consider emitting a clearer message when fallback to system scope is used at runtime

If the real-machine validation fails:

- inspect whether the failure is nftables syntax, cgroup matching, or systemd scope binding
- decide whether the fallback should move away from `systemd-run` entirely for some WSL setups
