# Stock-WSL Backend Options

## Why This Document Exists

The repo is useful today, but only up to a point.

On stock WSL, the supported backend is still `hook_only`.
That gives you better defaults and real guardrails, but it is not the same thing as kernel-enforced network containment.

This document compares realistic ways to build a stronger backend that still works on a normal WSL setup without asking users to swap kernels.

## What "Good Enough" Should Mean

A stronger stock-WSL backend should:

- work on the default Microsoft WSL kernel
- keep the default posture offline
- block or constrain actual network traffic, not just command text
- handle common developer flows such as `git`, package managers, and `curl`
- fail closed with clear errors
- avoid turning normal development into a permissions mess

## Current Baseline: `hook_only`

What it does well:

- blocks obvious direct network commands
- forces explicit profile selection for visible remote targets
- catches destructive shell actions early
- keeps Codex offline by default

What it cannot do:

- see the real destination for implicit commands such as `git fetch origin`
- stop arbitrary binaries that open sockets after launch
- provide packet-level enforcement on stock WSL

Conclusion:

- keep this as the supported baseline
- do not pretend it is the final answer

## Option 1: Proxy-First Backend

Idea:

- run a local policy proxy
- launch wrapped commands with `HTTP_PROXY`, `HTTPS_PROXY`, and related variables
- let the proxy allow or deny requests by profile

Why it is attractive:

- easier to prototype
- works for many HTTP-based tools
- good fit for `curl`, many package managers, and some SDKs

Why it is not enough:

- many tools ignore proxy variables
- SSH and non-HTTP protocols are awkward or unsupported
- arbitrary binaries can bypass the proxy entirely
- DNS handling is still messy

Verdict:

- useful as an intermediate improvement
- not strong enough to be the main long-term backend

## Option 2: Per-Profile Unix Users

Idea:

- create a dedicated Linux user per network profile
- launch wrapped commands as that user
- use firewall rules keyed to user identity instead of cgroup socket matching

Why it is attractive:

- avoids the missing `CONFIG_NFT_SOCKET` dependency
- user or owner based filtering is a simpler firewall model

Why it is dangerous for developer UX:

- file permissions get ugly fast
- repo writes may come out owned by the wrong user
- user HOME, SSH agent, git config, and tokens become harder to manage safely
- commands that need normal workspace access become fragile

Verdict:

- possible in theory
- poor fit for a developer workstation hardening bundle

## Option 3: Network-Namespace Backend

Idea:

- launch wrapped commands inside a dedicated Linux network namespace
- make that namespace offline by default
- only provide approved outbound paths for the selected profile
- use normal firewall and routing rules inside that isolated namespace

Why it is attractive:

- stronger than command-text inspection
- does not depend on `CONFIG_NFT_SOCKET`
- applies to the actual packets created by the wrapped command
- covers arbitrary binaries better than a proxy-only design

Why it is harder:

- namespace setup is more complex than a pure hook model
- likely needs `sudo` during setup and careful lifecycle cleanup
- DNS, loopback services, and local dev ports need explicit design
- WSL-specific quirks need real validation

Verdict:

- best long-term direction for a strong stock-WSL backend
- worth real engineering time

## Recommended Direction

Build toward a namespace-based backend.

Reason:

- it is the only option in this comparison that has a credible path to real traffic enforcement on stock WSL without forcing users onto a custom kernel
- it avoids the workspace-ownership problems of per-profile Unix users
- it is stronger and broader than a proxy-first design

## Practical Delivery Plan

### Stage 1: Make `hook_only` Worth Using

Short-term work:

- keep `hook_only` as the default and document its limits clearly
- improve `codex-net explain` style UX so users can understand why a command is blocked
- expand command-profile mappings for common developer workflows
- tighten messages around explicit versus implicit destinations

Exit condition:

- the baseline is honest, predictable, and low-friction

### Stage 2: Add A Limited Proxy Assist

Short-term optional step:

- add an opt-in local proxy mode for HTTP-heavy commands
- use it only as a convenience layer, not as the core security claim

Exit condition:

- common HTTP tooling gets smoother without overstating protection

### Stage 3: Prototype Namespace Execution

Core engineering step:

- create a namespace-backed `codex-net exec`
- keep loopback available when a profile allows local dev
- route approved outbound traffic through namespace-local policy
- prove that blocked destinations fail at runtime for implicit commands

Exit condition:

- a wrapped implicit command can run, but real traffic is still constrained by profile

### Stage 4: Validate On Real Stock WSL

Required before calling it supported:

- test on a default Microsoft WSL kernel
- document distro, systemd, package, and privilege requirements
- add install-time capability checks
- add clean failure and rollback behavior

Exit condition:

- stock-WSL users can set up the stronger backend without kernel replacement

## What Not To Do

Avoid these traps:

- do not market `hook_only` as true containment
- do not make a custom WSL kernel the default recommendation
- do not choose a backend that breaks normal repo file ownership
- do not rely on one transport-specific trick and call it comprehensive

## Bottom Line

Today, this repo is a useful guardrail bundle, not a complete containment system.

That is still worth something:

- safer defaults
- destructive-command blocking
- explicit profile-based network intent
- reduced ambient shell exposure

But if the goal is "strong stock-WSL network enforcement," the next serious move is a namespace-based backend, not more incremental work on the current nft socket design.
