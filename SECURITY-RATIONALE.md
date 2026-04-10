# Security Rationale

## Purpose

This repo exists to reduce the most common high-impact risks in a local Codex CLI setup without making Codex unusable for normal development work.

The goal is not to create a perfect containment boundary. The goal is to:

- lower the chance of accidental destructive actions
- lower the chance of straightforward prompt-injection-driven exfiltration
- reduce the amount of ambient secret material exposed to subprocesses
- preserve a workflow that still allows coding, testing, and normal repo operations

## Design Approach

The hardening model here is layered:

1. Codex defaults in `config.toml`
2. Coarse native command controls in `rules/default.rules`
3. Fine-grained shell inspection in `hooks/block_destructive.py`
4. Fine-grained shell egress checks in `hooks/block_network_egress.py`
5. Operator-maintained profiles in `policies/network_profiles.toml`

Each layer covers a different failure mode.

## Why This Is Codex-Oriented

This repo is intentionally built around Codex concepts and file locations:

- `~/.codex/config.toml`
- `~/.codex/hooks.json`
- `~/.codex/rules/*.rules`
- `PreToolUse` hooks for `Bash`
- `workspace-write` sandbox mode
- `approval_policy = "on-request"`

That is different from Claude-oriented setups, which typically revolve around `~/.claude/` and Claude-specific configuration surfaces.

## Inspiration and Credit

Credit to [AgentShield](https://github.com/affaan-m/agentshield), a security scanner oriented toward Claude agent configurations.

This repo is not a fork of AgentShield and does not attempt to reproduce its scanner. The contribution here is narrower:

- take the same agent-security mindset
- apply it to a Codex local runtime
- package a Codex-specific baseline that teams can review, share, and adapt

## Threat Model

This baseline is designed primarily around these risks:

1. Destructive shell execution
Codex can be asked to run shell commands. Some commands are routine and necessary; others are destructive enough that they should never be executed autonomously.

2. Network egress and exfiltration
If an agent can make arbitrary outbound requests, a prompt injection or malicious instruction can try to send secrets, repo contents, or environment material to an external host.

3. Excessive environment inheritance
Even if shell access is necessary, it is safer if subprocesses receive a smaller environment by default.

4. Unsafe convenience drift
A local setup tends to become more permissive over time. A shareable baseline keeps the default posture conservative and reviewable.

## Why These Controls Exist

### 1. `approval_policy = "on-request"`

This keeps a human approval step available when Codex decides a command needs one. It is a pragmatic middle ground between:

- a fully locked-down mode that blocks useful work too often
- a fully automatic mode that can execute too much with too little friction

### 2. `sandbox_mode = "workspace-write"`

This allows normal coding work in the project while avoiding a default posture of unrestricted host access.

The repo intentionally does not normalize `danger-full-access`.

### 3. `web_search = "cached"`

This keeps research capability lower risk by default than fully live open-web access. It is not a complete network defense, but it reduces one unnecessary source of unconstrained outbound interaction.

### 4. `[history] persistence = "none"`

This reduces new local transcript persistence. It does not retroactively erase old history, but it helps reduce future accumulation of sensitive prompt or output material in the Codex history store.

### 5. `[sandbox_workspace_write] network_access = false`

This is the first-line network control. If Codex does not have shell-network access in the sandbox by default, many exfiltration paths fail early.

### 6. Reduced `shell_environment_policy`

Subprocesses should not inherit a large ambient environment by default. If secrets are not present in the child process environment, they are harder to leak through accidental or malicious shell actions.

### 7. Native execpolicy rules

`rules/default.rules` provides coarse policy for command prefixes that are rarely justifiable for autonomous execution.

Examples:

- `sudo`
- `mkfs`
- `shred`
- `wipefs`
- `git reset --hard`
- `git clean`

These rules are simple, reviewable, and Codex-native.

### 8. Destructive-command hook

The destructive hook exists because not every dangerous command is well-expressed as a simple static prefix rule.

The hook is intended to catch commands such as:

- recursive deletion at root or home
- direct device overwrite patterns
- force-push variants
- process or system control actions that should remain manual

The operational rule is simple: if the command is risky enough that human intent should be explicit, Codex should stop and the operator should run it manually if they truly want it.

### 9. Profile-based network hook

The network hook exists because shell egress is one of the most useful exploitation paths against coding agents.

The hook focuses on explicit shell networking tools:

- `curl`
- `wget`
- `ssh`
- `scp`
- `rsync`
- `nc` / `ncat` / `netcat`

It allows:

- localhost and loopback targets when the selected profile allows them
- explicit remote targets that fit the selected profile
- wrapped commands that use `codex-net exec --profile ... -- ...`

It blocks:

- remote destinations outside the selected profile
- implicit network commands when the backend cannot verify the actual destination
- ambiguous raw socket use
- dynamic destinations such as `$URL` that cannot be safely verified from the literal command string

On stock WSL today, this hook-driven path is the supported network control model. That means implicit network commands may still require a human decision even when the profile model exists, because the stronger nft-backed backend depends on kernel support that is not present on the default Microsoft WSL kernel validated for this repo.

## What This Repo Does Not Claim

This baseline is useful, but limited.

It does not claim to stop:

- shell obfuscation tricks in the general case
- alias abuse outside the inspected command string
- non-shell exfiltration paths
- DNS tunneling
- malicious local binaries
- actions run directly by a human outside Codex
- every possible prompt-injection path through every future Codex surface

It is a practical baseline, not a formal sandbox or a complete adversarial defense.

## Why This Repo Is Shareable

The shareable repo intentionally excludes:

- `history.jsonl`
- `auth.json`
- local SQLite state
- personal trusted-project entries
- machine-specific plugin state

That makes it appropriate for team review and reuse while keeping personal local runtime data out of source control.

## Recommended Team Usage

Use this repo as:

- a reviewed baseline
- a starting point for internal policy discussions
- a template to adapt to each developer environment

Do not treat it as immutable. Teams should expect to tune:

- the profiles
- the destructive-command patterns
- which operations are manual-only versus approval-gated

## Bottom Line

The core philosophy is simple:

- let Codex do normal coding work
- keep the default runtime constrained
- make destructive actions manual
- make outbound shell networking explicit and reviewable
- keep the policy small enough that humans will actually maintain it
