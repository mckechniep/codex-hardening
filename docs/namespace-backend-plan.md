# Namespace Backend Plan

## Purpose

This document turns Phase 5 into an implementation plan.

The goal is a stronger stock-WSL-compatible backend that does not depend on nft's `socket cgroupv2` expression and therefore does not require `CONFIG_NFT_SOCKET`.

Working backend name:

- `linux_wsl_netns`

## Implementation Status

The first-pass execution path is implemented.

Today, `linux_wsl_netns` can:

- install base runtime nftables scaffolding with `codex-net apply-rules --sudo`
- report backend state with `codex-net backend-status`
- run `codex-net exec --profile ... -- ...` in a transient namespace
- create a veth pair and default route for each wrapped command
- apply per-execution nftables rules keyed to the namespace interface and subnet
- run the wrapped command as the original user
- clean up per-execution namespace, veth, nftables, and state artifacts on normal exit

Still planned:

- local policy DNS stub
- garbage collection for orphaned runtime artifacts
- friendlier local-dev exposure helpers
- broader real-host validation

## Success Criteria

This backend is worth shipping only if it can do all of the following on a normal WSL 2 setup:

- keep the default posture offline
- constrain real packet egress for wrapped commands
- handle implicit network commands such as `git fetch origin`
- preserve normal workspace file ownership
- fail closed when setup is incomplete
- clean up after crashes and partial setup failures

## Core Design

Use an ephemeral Linux network namespace per wrapped execution.

That namespace:

- starts with no external network access
- gets a dedicated veth pair to the host namespace
- uses a namespace-local default route through the host side of that veth
- currently uses generated `hosts` files for explicit domain profiles and host resolver config for wildcard profiles; the target design is still a local policy DNS stub
- is governed by host-side nftables rules keyed to namespace interface and subnet, not cgroup socket matching

This avoids the kernel feature that blocked `linux_wsl_nft` on stock WSL.

## Why Ephemeral Namespaces

Use one namespace per wrapped command, not one long-lived namespace per profile.

Reasons:

- avoids cross-command state leakage
- makes cleanup easier to reason about
- keeps per-command policy application explicit
- avoids stale connections and namespace drift

Tradeoff:

- startup cost is higher

That is acceptable for the first serious backend because wrapped network commands should be less frequent than normal offline editing commands.

## Command Lifecycle

### 1. Hook Layer

The existing hook layer keeps its current role:

- detect likely network intent
- suggest or require a profile
- block direct network use outside the wrapper

Example:

- direct `git fetch origin` is blocked
- operator or Codex retries with `codex-net exec --profile git_readonly -- git fetch origin`

### 2. Wrapper Validation

`codex-net exec` performs user-space validation first:

- load and validate `network_profiles.toml`
- confirm the selected profile exists
- inspect explicit destinations when visible in the command text
- reject obviously disallowed explicit targets before any privileged setup
- run backend capability checks

### 3. Backend Preflight

Before namespace creation, the backend checks:

- WSL 2
- `sudo`
- `ip`
- `nft`
- `CONFIG_NET_NS`
- `CONFIG_VETH`
- nft NAT and filter support

It should also verify:

- a writable state directory
- lock acquisition ability
- whether the DNS stub and base nft table are installed if the backend uses persistent base assets

### 4. Namespace Allocation

For each wrapped execution:

- allocate an execution ID
- allocate a namespace name such as `codex-net-<exec-id>`
- allocate a small subnet and deterministic host/guest IP pair
- create a veth pair
- move one side into the namespace
- bring up loopback inside the namespace
- assign guest IP and route default traffic to the host-side veth address

### 5. DNS Wiring

The namespace must not talk to arbitrary external resolvers.

Current first pass:

- explicit domain profiles get a namespace-local `hosts` file and a dead-end `resolv.conf`
- wildcard profiles such as `relaxed_network` use the host resolver config and allow any remote address on the profile's approved ports

Target design:

Instead:

- `/etc/resolv.conf` inside the namespace points only to a local policy DNS stub on the host-side veth address
- the stub resolves only domains allowed by the selected profile
- all other DNS queries are denied

This gives the backend a real answer to DNS leakage that the current profile compiler does not have.

### 6. Firewall Installation

The host namespace installs runtime nftables rules for that execution:

- allow namespace traffic only from the namespace subnet or veth interface
- allow DNS only to the local policy stub
- allow outbound traffic only to approved destination IP sets and ports for the selected profile
- drop or reject everything else
- apply NAT or masquerade on approved outbound traffic when needed

The policy key is the namespace network path, not a cgroup match.

### 7. Command Launch

The wrapped command should still run as the original user so workspace writes stay owned by that user.

Execution model:

- privileged helper creates the namespace and network assets
- helper then launches the command inside the namespace as the original user
- environment is still reduced according to Codex hardening policy

The command exits with its real exit code.

### 8. Teardown

On command exit:

- remove the runtime nft rules for that execution
- stop any per-exec DNS helper state
- delete the namespace
- delete the veth pair
- clear the execution state record

Teardown must run on:

- normal completion
- signal interruption
- launch failure after partial setup

## Namespace Setup Model

### Base Assets

The backend should install only a small persistent base:

- one nft table namespace for codex-net runtime chains
- optional bridge or host-side helper chain structure
- optional local DNS stub service
- a state directory and lock file

This should be prepared once with a privileged command such as:

- `codex-net apply-rules --sudo`

For this backend, `apply-rules` is better thought of as:

- install or refresh base runtime infrastructure

It should not try to pre-create one ruleset per future execution.

### Per-Execution Assets

Everything that identifies one wrapped command should be ephemeral:

- namespace name
- veth pair
- subnet
- runtime nft set references
- execution state file

## DNS Model

### Recommended DNS Design

Use a local policy stub rather than direct profile compilation of remote DNS answers.

Why:

- profile-approved domains can resolve dynamically
- DNS leakage can be blocked cleanly
- the backend can support hostnames instead of only precompiled IP snapshots

Behavior:

- if a domain is allowed by profile, resolve it using the host resolver path
- cache answers briefly
- return only A and AAAA records
- deny all queries outside the profile

### Fallback DNS Behavior

If the DNS stub is unhealthy:

- fail closed for wrapped commands

Do not silently fall back to external resolvers.

Current caveat: wildcard profiles intentionally use the host resolver config because their policy already allows any remote address on selected ports. Explicit domain profiles still fail closed when their allowed domains cannot be resolved before launch.

## Local-Dev Allowances

Local development needs explicit handling because `127.0.0.1` inside the namespace is not the same as host loopback.

### Rule

Treat host-local development as a separate access mode, not as a side effect of "localhost allowed."

### First-Pass Model

Use a stable host-side gateway IP for each namespace and let the `dev_local` profile allow only:

- the host gateway IP
- explicitly approved local ports

That means local dev services must be reachable on the host namespace via:

- `0.0.0.0`
- a concrete WSL-side IP
- or an explicit published forward

### Optional Helper

Add a helper later such as:

- `codex-net expose-local --port 3000`

That helper can publish a host loopback service onto the namespace gateway path without opening more than the approved port.

## Cleanup And Rollback

### Transaction Model

Namespace setup must be transactional.

If any step fails:

- tear down everything created so far
- return a clear error that names the failed step

Examples:

- veth creation succeeded but nft rule install failed
- namespace exists but command launch failed
- DNS stub wiring failed after route creation

In all of those cases, the backend should remove partial runtime assets before returning.

### Crash Recovery

Add a garbage-collection command:

- `codex-net gc --sudo`

It should:

- remove orphaned namespaces matching the backend naming pattern
- remove orphaned veth pairs
- remove stale runtime nft chains and sets
- reconcile the state directory with live kernel objects

## Status And Explainability

Add or extend:

- `codex-net backend-status`
- `codex-net explain <command>`

`backend-status` should report:

- whether base assets exist
- whether the DNS stub is healthy
- whether stale runtime artifacts were found

`explain` should report:

- selected profile
- whether the command will run in `hook_only` or namespace mode
- whether local-dev allowances are involved
- which DNS and destination rules will apply

## Minimal Delivery Sequence

### Phase 5A: Feasibility Spike

- add doctor checks for namespace-related kernel and tooling support
- prove namespace creation, veth setup, and cleanup on stock WSL
- prove wrapped command launch inside a namespace as the original user

Status: implemented.

### Phase 5B: Base Runtime

- add persistent base nft table and locking
- add execution state tracking
- add rollback-safe helper functions

Status: implemented.

### Phase 5C: First-Pass Profile Enforcement

- translate profiles into runtime destination rules
- enforce ports and explicit-domain destinations on the namespace subnet
- support wildcard profiles on approved ports
- validate real allow and deny cases for implicit commands

Status: implemented as a first pass with generated `hosts` files and host resolver config for wildcard profiles.

### Phase 5D: DNS Control

- add the local policy DNS stub
- wire namespace `resolv.conf` to the stub for explicit domain profiles
- deny direct external DNS from wrapped namespaces

Status: planned.

### Phase 5E: Local Dev

- add explicit `dev_local` handling
- validate access to host-side dev servers on approved ports only

### Phase 5F: Recovery And UX

- add `gc`
- improve `backend-status`
- add clearer operator guidance and failure messages

## Open Questions

- should the DNS stub be per-exec, per-profile, or one shared process with profile-aware policy
- should base runtime install create a bridge, or should each execution use point-to-point veth only
- what is the simplest host-local forwarding mechanism for `dev_local`
- how much concurrency should be supported in the first implementation

## Bottom Line

If this repo wants a serious stock-WSL backend, the path is:

- keep `hook_only` as the honest baseline
- stop investing in the current nft socket design for stock WSL
- build `linux_wsl_netns` around ephemeral namespaces, local policy DNS, and host-side nftables keyed to namespace network paths
