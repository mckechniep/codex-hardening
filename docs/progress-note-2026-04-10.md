# Progress Note: 2026-04-10

## Current State

The repo now has three distinct network-control paths:

- Codex config and execpolicy hardening
- shell-hook network detection and wrapper enforcement
- two WSL backends:
  - `linux_wsl_nft` for kernels that support `CONFIG_NFT_SOCKET`
  - `linux_wsl_netns` as the stock-WSL replacement under active development

The `linux_wsl_netns` work has now moved past the one-shot feasibility spike and base-runtime scaffolding.
Normal `codex-net exec` can run wrapped commands through the namespace backend when the backend is selected and prepared.

## What Landed In This Slice

- `codex-net apply-rules --sudo` now has a `linux_wsl_netns` path that writes and applies a base runtime nftables table instead of profile-compiled nft rules.
- `codex-net backend-status` now understands `linux_wsl_netns` state, including whether the recorded base rules file still exists and still matches its recorded hash.
- `codex-net remove-rules --sudo` now refuses to tear down the netns base runtime while execution records still exist.
- the namespace backend now keeps a runtime lock and execution-record directory under the codex-net state root
- `codex-net exec --profile ... -- ...` now creates a transient namespace, applies per-execution nftables rules, launches the command as the original user, and cleans up after exit
- explicit profile domains are written into a namespace-local `hosts` file
- wildcard profiles use host resolver config and allow any remote address on approved ports
- install now ships `codex_net_netns.py`
- tests now cover the new netns base-runtime apply/status behavior

## What Is Still Missing

The first-pass execution path is implemented, but it still has deliberate limitations:

- local policy DNS stub wiring is not implemented yet
- explicit `localhost` targets are rejected because namespace loopback is not host loopback
- host-local development currently uses `$CODEX_NET_HOST_GATEWAY`
- crash garbage collection is still future work

## Recommended Next Step

Harden the real `linux_wsl_netns` execution path:

1. add the local policy DNS stub
2. add `codex-net gc --sudo` for orphaned namespace/veth/rules cleanup
3. improve local-dev helper UX around `$CODEX_NET_HOST_GATEWAY`
4. validate allowed and denied real traffic on stock WSL hosts
5. keep installer and README guidance aligned with the exact backend readiness state

DNS stub wiring is still part of the design target, but the current implementation remains explicit about its temporary DNS limitations.
