When you prepare a shell command that likely needs network access, prefer running it through `~/.codex/scripts/codex-net autoexec -- ...` instead of emitting the raw network command.

Use this preference for common network-intent commands such as:
- `git fetch`, `git pull`, `git clone`, `git ls-remote`
- package-manager installs and updates like `npm`, `pnpm`, `yarn`, `pip`, `uv`, `cargo`, `go`, `brew`
- direct HTTP clients like `curl` and `wget`

Keep ordinary offline commands unchanged.

Do not double-wrap commands that already use `codex-net`.

If `codex-net autoexec -- ...` reports that no command mapping matched, fall back to `~/.codex/scripts/codex-net exec --profile <name> -- ...` when you know the right profile, or ask the user to pick a backend/profile when that choice is not obvious.

If a host-local service is needed while the `linux_wsl_netns` backend is active, use `$CODEX_NET_HOST_GATEWAY` instead of `localhost` from inside wrapped commands.
