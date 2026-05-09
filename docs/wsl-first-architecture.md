# WSL-First Network Enforcement Architecture

## Purpose

This document defines the WSL network-enforcement direction for this repo.

The current baseline hardening is useful, but the hook layer is still command-text inspection. It can block obvious `curl` and `ssh` usage, but it cannot reliably stop all network-capable binaries.

The WSL-first backend fixes that by moving real blocking into the Linux networking layer while keeping Codex customization in user-editable policy files.

Current backend state:

- `hook_only` is the default lightweight backend and performs command-string validation only
- `linux_wsl_netns` is the stock-WSL-compatible stronger backend and uses transient network namespaces plus nftables
- `linux_wsl_nft` is still available for kernels with nft socket/cgroup support, but it is conditional and not the stock-WSL default
- a real validation run on `6.6.87.2-microsoft-standard-WSL2` on April 9, 2026 found that `CONFIG_NFT_SOCKET` was not enabled, which makes `linux_wsl_nft` unavailable on that stock kernel even though `nft`, `sudo`, cgroup v2, and systemd are present

## Scope

First implementation target:

- Codex CLI running inside `WSL 2`
- Linux-side enforcement only
- real outbound blocking for wrapped commands
- user-editable profiles that allow or deny specific destinations

Explicitly out of scope for the first pass:

- Codex running on Windows outside WSL
- packet inspection or content filtering
- full DNS exfiltration prevention
- macOS parity

## Why WSL First

WSL gives this repo a Linux kernel and Linux networking primitives, which are the right place to enforce actual socket behavior.

That means the first pass can rely on:

- `nftables`
- `cgroup v2`
- normal Linux process launch wrappers
- optional `systemd` integration where available

This is materially stronger than hook-only inspection and much easier to reason about than a macOS-first backend.

## Design Goals

- keep Codex usable for normal development
- keep default posture offline
- allow temporary and permanent user customization
- make allowed network access explicit and profile-based
- enforce policy below the shell-command layer
- keep the policy model portable enough for a later macOS backend

## Non-Goals

- perfect containment
- transparent handling of every possible network command with zero model adaptation
- identical backend behavior across Linux and macOS

## High-Level Model

There are now two layers:

1. Codex policy layer
- hook decides whether a command appears to need network
- hook decides which profile should be used, or blocks with guidance

2. Linux enforcement layer
- wrapped command runs in a restricted execution context
- `nftables` enforces actual outbound destination limits
- any binary in that context is subject to the same packet policy, including `python`, `node`, `git`, and custom executables

## Execution Flow

Default flow:

1. Codex runs in `workspace-write` with `network_access = false`.
2. Normal coding commands stay inside the default sandbox and remain offline.
3. If a command needs network, the hook blocks direct execution and tells Codex to retry using the network wrapper.
4. Codex reruns the command as:
   `codex-net exec --profile <profile> -- <command> ...`
5. The wrapper places the command into the selected enforcement context.
6. `nftables` allows only the destinations permitted by that profile.

This keeps the default case simple while still allowing higher-function workflows when the user explicitly permits them through profiles.

## Why Wrapper-Based Execution

Codex does not currently expose a syscall-aware post-launch policy hook. The practical control point available to this repo is still command launch.

The wrapper is the bridge between:

- Codex intent and approval logic
- real Linux-side egress enforcement

This is also what keeps the design adaptable: the same `codex-net exec --profile ...` interface can later map to a different backend on macOS.

## Backend Contract

Current backends are:

- `hook_only`: low-friction command validation, no packet isolation
- `linux_wsl_netns`: transient namespace and nftables enforcement for stock WSL
- `linux_wsl_nft`: systemd slice plus nft socket/cgroup matching for kernels that support `CONFIG_NFT_SOCKET`

The stronger backend is responsible for:

- preparing or refreshing runtime enforcement assets
- launching a command in the restricted execution context
- applying `nftables` rules that bind egress to that context or namespace
- surfacing backend capability checks and actionable errors

Future backends:

- `mac_pf_limited`

The policy model should not depend on one specific backend.

## WSL Backend Requirements

Hard requirements:

- WSL 2
- `nftables`
- `python3`
- `sudo` available during install and backend setup

Strongly recommended:

- `systemd` enabled in WSL

Reason:

- a systemd-enabled WSL distro is easier to manage for long-lived refresh tasks and delegated execution scopes

## Enforcement Strategy

Kernel-dependent `linux_wsl_nft` design:

- commands that need network are launched under a dedicated `codex-net` cgroup hierarchy
- `nftables` uses socket-to-cgroup matching to identify packets belonging to those commands
- profile-specific sets define which destination IPs and ports are allowed

Stock-WSL `linux_wsl_netns` design:

- each wrapped command gets a transient network namespace
- host-side nftables rules key policy to the namespace veth/subnet
- the command runs as the original user inside that namespace so workspace file ownership is preserved

This backend should treat all traffic from the wrapped process the same way, regardless of which binary created the socket.

This is the key security improvement over the current hook-only model.

## DNS Reality In The First Pass

Important limitation:

- firewalls work on IPs and ports, not domain names

Therefore the control plane has to resolve allowed domains into address sets before command launch.

Current compromises:

- `linux_wsl_nft` resolves allowed domains to A and AAAA records and writes them into profile-specific `nftables` sets
- `linux_wsl_netns` writes explicit profile domains into a namespace-local `hosts` file
- wildcard profiles such as `relaxed_network` use the host resolver config and allow any remote address on the profile's approved ports
- a local policy DNS stub remains the better long-term design

This blocks arbitrary TCP and UDP egress to most destinations, but it does not fully solve DNS-only leakage in the first pass.

Phase-two option:

- route wrapped commands through a local stub resolver and only allow DNS to localhost

## Policy Model

The user-facing policy remains editable text, not code.

Core concepts:

- backend selection
- default profile
- named profiles
- command-to-profile mappings
- temporary grants

Each profile can define:

- description
- allowed domains
- allowed TCP ports
- allowed UDP ports
- localhost allowance
- approval behavior
- expiry or TTL for temporary grants

## Example Profiles

The first pass should ship with profiles like:

- `offline`
  No remote network
- `registries`
  Package registries and source download hosts
- `git_readonly`
  Git remote reads and clones
- `dev_local`
  Loopback and local service ports for browserless dev workflows
- `custom`
  User-managed profile entries

## Codex Integration Strategy

The current hook remains useful, but its role changes.

Instead of pretending to be the final enforcement layer, it becomes:

- a detector for likely network intent
- a profile suggester
- a guardrail that blocks direct network execution outside the wrapper

Example behavior:

- direct `curl https://github.com` is denied
- hook responds with guidance to use `codex-net exec --profile registries -- curl https://github.com`
- Codex can retry in the correct form

The hook is still heuristic. The backend is where actual egress blocking happens.

## File Layout For The First Pass

Current files:

- `docs/wsl-first-architecture.md`
- `templates/network-profiles.template.toml`
- `policies/network_profiles.toml`
- `scripts/codex-net`
- `scripts/codex_net_backend.py`
- `scripts/codex_net_policy.py`
- `scripts/codex_net_wsl.py`
- `scripts/codex_net_netns.py`
- `hooks/block_network_egress.py`

Probable responsibilities:

- `scripts/codex-net`
  Stable user-facing wrapper entrypoint
- `scripts/codex_net_backend.py`
  Backend selection, capability checks, and command launch
- `scripts/codex_net_policy.py`
  Profile loading, command inspection, and user-space policy validation
- `scripts/codex_net_wsl.py`
  Kernel-dependent nft/socket backend support
- `scripts/codex_net_netns.py`
  Namespace backend support

## Installer Changes

The installer now:

- copies policy templates, hooks, wrapper, and helper scripts
- merges hardening settings into `~/.codex/config.toml`
- repairs known unsafe managed settings while preserving unrelated user settings
- merges network profile defaults into `~/.codex/policies/network_profiles.toml`
- performs backend readiness reporting through `codex-net doctor`
- prints exact backend selection and rollback commands

The installer keeps this safety posture:

- merge local config where possible
- back up anything it changes
- never silently replace unrelated user configuration

## macOS Follow-On

The macOS backend should reuse:

- the same policy model
- the same wrapper interface
- the same command-to-profile mapping

It should not promise the same enforcement internals.

Likely backend:

- `mac_pf_limited`

Expected differences:

- coarser per-process control
- more backend-specific caveats
- likely weaker isolation than WSL/Linux

That is why the backend interface must be explicit from the start.

## Implementation Phases

Phase 1:

- add profile file format
- add wrapper entrypoint
- change hook to require wrapped execution for networked commands

Phase 2:

- add WSL capability checks
- add `nftables` set compiler from domain profiles
- add profile refresh flow

Phase 3:

- add cgroup-bound execution and actual packet filtering
- verify arbitrary binaries are constrained, not just known command names

Phase 4:

- add namespace-backed execution for stock WSL
- add temporary grants
- add better DNS handling
- add macOS backend scaffold

## Success Criteria

The WSL enforcement path is successful if:

- Codex stays offline by default
- wrapped commands can access only profile-approved destinations
- `python -c`, `node -e`, `git`, and custom binaries are all constrained under the same wrapper
- users can tune policy without editing Python
- the macOS backend can reuse the policy model later
