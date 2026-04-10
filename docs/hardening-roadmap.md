# Hardening Roadmap

This roadmap is intentionally biased toward correctness first. A security bundle that blocks the wrong commands or cannot be tested reliably will either be bypassed or removed.

## Phase 1: Correctness And Regression Coverage

Goal: make the shipped defaults predictable and testable.

- Keep ordinary non-network Bash commands out of the network-policy path by default.
- Add regression tests for both hooks, not just WSL helper logic.
- Keep `python3 -m unittest -v` green from the repo root.
- Add focused unit tests for:
  - `select_profile_for_command`
  - `collect_network_requests`
  - `validate_command_for_profile`
  - `merge_hooks.py`
- Add fixture-based tests for nested shell wrappers such as `bash -lc`, `env VAR=...`, and segmented commands with `&&` and `;`.

Exit criteria:

- Hook regressions are caught before install.
- Test discovery works without custom invocation.
- The installed default policy does not block routine offline commands.

## Phase 2: Policy Model Tightening

Goal: make the hook layer conservative without becoming noisy.

- Separate "network intent detected" from "profile suggestion available" in the policy API.
- Add an explicit ambiguous-command path for commands that imply network access but hide the destination.
- Cover more package-manager and source-control flows:
  - `uv sync`
  - `uv pip install`
  - `pip download`
  - `npm ci`
  - `pnpm install`
  - `yarn install`
  - `go get`
  - `cargo install`
  - `git ls-remote`
- Add tests for dynamic destinations and wrapper recursion.
- Keep profile-based policy as the single supported model; do not reintroduce a legacy JSON allowlist fallback.

Exit criteria:

- The hook layer has a documented answer for explicit, implicit, dynamic, and unknown network intent.
- Command coverage matches common developer workflows instead of only `curl` and `git clone`.

## Phase 3: WSL Backend Validation

Goal: turn the `linux_wsl_nft` backend from promising code into a validated control.

- Validate `doctor`, `apply-rules`, `backend-status`, `exec`, and `remove-rules` on a real WSL 2 host.
- Capture known-good environment requirements:
  - distro
  - kernel details
  - `nftables` package name
  - systemd configuration
- Add tests around generated nftables output shape and backend state transitions.
- Add a verification step that confirms the expected nftables table and chain exist after apply.
- Verify that backend readiness and apply-state checks fail closed when the configured systemd manager or prepared slice units are missing.
- Add an explicit host capability gate for kernels that do not enable `CONFIG_NFT_SOCKET`.

Exit criteria:

- Real-machine validation has been completed and documented.
- Backend failures produce actionable messages instead of ambiguous policy errors.

## Phase 3.5: Stock-WSL Support Posture

Goal: make the supported path explicit for normal users.

- Treat `hook_only` as the supported default on stock WSL.
- Keep `linux_wsl_nft` available only behind explicit kernel-capability checks.
- Tighten install and README guidance so normal users are not pushed toward unsupported kernel-level setup.

Exit criteria:

- A beginner on stock WSL is guided toward `hook_only` by default.
- Kernel-dependent paths are clearly labeled as conditional.

## Phase 4: Operator UX And Recovery

Goal: make hardening maintainable instead of fragile.

- Add `install.sh --dry-run`.
- Add a rollback helper that restores the last backup cleanly.
- Add a policy linter for `network_profiles.toml`.
- Add a `codex-net explain <command>` mode that shows:
  - whether the command looks networked
  - which profile would be selected
  - why it would be allowed or denied
- Improve README examples around common workflows and failure modes.

Exit criteria:

- Operators can preview, install, explain, and roll back policy changes without editing Python.

## Phase 5: Deeper Security Work

Goal: improve real protection rather than just policy expression.

- Route wrapped command DNS through a local stub resolver when using the WSL backend.
- Revisit whether DNS-only leakage needs stronger first-class controls.
- Design a stock-WSL-compatible stronger backend that does not depend on `CONFIG_NFT_SOCKET`.
- Bias that design toward a namespace-based backend instead of a user-identity workaround or a proxy-only model. See `docs/stock-wsl-backend-options.md`.
- Turn that backend into an implementation plan covering command lifecycle, namespace setup, DNS control, local-dev allowances, and cleanup or rollback. See `docs/namespace-backend-plan.md`.
- Reduce exposure of ambient credentials and tokens during wrapped execution.
- Consider lightweight telemetry or audit logs for blocked and wrapped commands.
- Review whether additional non-shell surfaces in Codex need hardening beyond Bash hooks.

Exit criteria:

- The bundle protects against more than obvious shell misuse and leaves an audit trail operators can review.

## Non-Goals

These are still out of scope unless the architecture changes:

- perfect containment
- human-run command restriction outside Codex
- complete defense against arbitrary local binaries
- platform parity across Linux, WSL, macOS, and Windows in one pass
