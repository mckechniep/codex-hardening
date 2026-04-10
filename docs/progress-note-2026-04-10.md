# Progress Note: 2026-04-10

## Current State

The repo now has three distinct network-control paths:

- Codex config and execpolicy hardening
- shell-hook network detection and wrapper enforcement
- two WSL backends:
  - `linux_wsl_nft` for kernels that support `CONFIG_NFT_SOCKET`
  - `linux_wsl_netns` as the stock-WSL replacement under active development

The `linux_wsl_netns` work has now moved past the one-shot feasibility spike.
It has base runtime installation and backend-state verification, but it does not yet run wrapped commands through the namespace backend during normal `codex-net exec`.

## What Landed In This Slice

- `codex-net apply-rules --sudo` now has a `linux_wsl_netns` path that writes and applies a base runtime nftables table instead of profile-compiled nft rules.
- `codex-net backend-status` now understands `linux_wsl_netns` state, including whether the recorded base rules file still exists and still matches its recorded hash.
- `codex-net remove-rules --sudo` now refuses to tear down the netns base runtime while execution records still exist.
- the namespace backend now keeps a runtime lock and execution-record directory under the codex-net state root
- install now ships `codex_net_netns.py`
- tests now cover the new netns base-runtime apply/status behavior

## What Is Still Missing

Normal wrapped execution is still not implemented for `linux_wsl_netns`.

Today, if `backend = "linux_wsl_netns"` is selected:

- `codex-net doctor` can report whether the host looks capable
- `codex-net netns-spike --sudo -- ...` can still validate create/run/cleanup mechanics
- `codex-net apply-rules --sudo` can install base runtime scaffolding
- `codex-net backend-status` can verify that scaffolding
- `codex-net exec --profile ... -- ...` still refuses normal execution

That means the next code slice is no longer "can a namespace be created on stock WSL?".
The next slice is "run the real wrapped command lifecycle through `linux_wsl_netns` with per-execution setup, cleanup, and fail-closed preflight."

## Recommended Next Step

Implement the real `linux_wsl_netns` execution path behind `codex-net exec`:

1. require recorded base runtime state before launch
2. allocate one execution record per wrapped command
3. create namespace and veth assets transactionally
4. install per-execution nft rules keyed to the execution subnet or interface
5. run the wrapped command as the original user inside the namespace
6. remove per-execution rules and runtime assets on both success and failure

DNS stub wiring is still part of the design target, but it does not need to block the first real `exec` path if the first implementation remains explicit about its temporary DNS limitations.
