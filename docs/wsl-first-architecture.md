# WSL-First Network Enforcement Architecture

## Purpose

This document defines the first real network-enforcement backend for this repo.

The current baseline hardening is useful, but the hook layer is still command-text inspection. It can block obvious `curl` and `ssh` usage, but it cannot reliably stop all network-capable binaries.

The WSL-first backend fixes that by moving real blocking into the Linux networking layer while keeping Codex customization in user-editable policy files.

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

The first backend is:

- `linux_wsl_nft`

It is responsible for:

- preparing or refreshing destination allowlists
- launching a command in the restricted execution context
- applying `nftables` rules that bind egress to that context
- surfacing backend capability checks and actionable errors

Future backends:

- `hook_only`
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

Primary design:

- commands that need network are launched under a dedicated `codex-net` cgroup hierarchy
- `nftables` uses socket-to-cgroup matching to identify packets belonging to those commands
- profile-specific sets define which destination IPs and ports are allowed

This backend should treat all traffic from the wrapped process the same way, regardless of which binary created the socket.

This is the key security improvement over the current hook-only model.

## DNS Reality In The First Pass

Important limitation:

- firewalls work on IPs and ports, not domain names

Therefore the control plane has to resolve allowed domains into address sets before command launch.

First-pass compromise:

- profile compiler resolves allowed domains to A and AAAA records
- resolved addresses are written into profile-specific `nftables` sets
- DNS traffic needed for hostname lookup is allowed in a narrow, explicit way for the wrapped command

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

Planned additions:

- `docs/wsl-first-architecture.md`
- `templates/network-profiles.template.toml`
- `policies/network_profiles.toml`
- `scripts/codex-net`
- `scripts/codex_net_backend.py`
- `scripts/codex_net_compile_profiles.py`
- `templates/nftables/codex-hardening.nft`
- `hooks/block_network_egress.py`

Probable responsibilities:

- `scripts/codex-net`
  Stable user-facing wrapper entrypoint
- `scripts/codex_net_backend.py`
  Backend selection, capability checks, and command launch
- `scripts/codex_net_compile_profiles.py`
  Resolve domains and render backend rule inputs
- `templates/nftables/codex-hardening.nft`
  Generated or templated `nftables` ruleset

## Installer Changes

The installer should eventually grow in two stages.

Stage 1:

- copy policy templates
- install wrapper and helper scripts
- perform capability checks
- print exact WSL prerequisites and next steps

Stage 2:

- optional privileged setup for `nftables`
- optional cgroup or delegated-scope setup
- optional scheduled refresh for resolved domain sets

The installer should keep the same safety posture as today:

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

- add temporary grants
- add better DNS handling
- add macOS backend scaffold

## Success Criteria

This first backend is successful if:

- Codex stays offline by default
- wrapped commands can access only profile-approved destinations
- `python -c`, `node -e`, `git`, and custom binaries are all constrained under the same wrapper
- users can tune policy without editing Python
- the macOS backend can reuse the policy model later
