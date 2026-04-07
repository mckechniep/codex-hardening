#!/usr/bin/env python3

import json
import shlex
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
WRAPPER_PATH = SCRIPTS_DIR / "codex-net"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from codex_net_policy import (
    NETWORK_TOOLS,
    PolicyError,
    collect_network_requests,
    iter_literal_commands,
    load_legacy_allowlist,
    load_network_profiles,
    parse_codex_net_exec,
    select_profile_for_command,
    split_segments,
    strip_wrappers,
    tokenize,
    validate_command_against_allowlist,
    validate_command_for_profile,
)


def read_payload() -> dict:
    try:
        return json.load(sys.stdin)
    except Exception:
        return {}


def deny(message: str) -> None:
    sys.stderr.write(
        f"Blocked by ~/.codex/hooks/block_network_egress.py: {message} "
        "If you intend this network action, use codex-net with an allowed profile, "
        "run it yourself outside Codex, or update your network policy first.\n"
    )
    raise SystemExit(2)


def wrapped_command_text(profile: str, nested_tokens: list[str]) -> str:
    nested = shlex.join(nested_tokens)
    wrapper = shlex.quote(str(WRAPPER_PATH))
    return f"{wrapper} exec --profile {profile} -- {nested}".strip()


def profile_mode(command: str, config: dict) -> None:
    for candidate in iter_literal_commands(command):
        for segment in split_segments(tokenize(candidate)):
            resolved = strip_wrappers(segment)
            if not resolved:
                continue
            executable, args = resolved

            if executable == "codex-net":
                parsed = parse_codex_net_exec(args, config["default_profile"])
                if not parsed:
                    continue
                profile_name, nested_tokens = parsed
                if not nested_tokens:
                    deny("`codex-net exec` requires a wrapped command after `--`.")
                try:
                    validate_command_for_profile(shlex.join(nested_tokens), profile_name, config)
                except PolicyError as exc:
                    deny(str(exc))
                continue

            segment_text = shlex.join(segment)
            requests = collect_network_requests(segment_text)
            suggested_profile = select_profile_for_command(config, segment_text)
            if not suggested_profile and not requests:
                continue

            if suggested_profile and not requests and config["backend"] == "hook_only":
                deny(
                    f"This command maps to network profile `{suggested_profile}`, but the hook_only backend "
                    "cannot verify its actual destination from the command text. Use a command with an explicit "
                    "remote target, keep it manual, or switch to linux_wsl_nft when that backend is ready."
                )

            suggested_profile = suggested_profile or "<profile>"
            deny(
                "Direct network commands must use codex-net. "
                f"Retry as `{wrapped_command_text(suggested_profile, segment)}`."
            )


def allowlist_mode(command: str) -> None:
    try:
        validate_command_against_allowlist(command, load_legacy_allowlist())
    except PolicyError as exc:
        deny(str(exc))


def main() -> None:
    payload = read_payload()
    command = str(payload.get("tool_input", {}).get("command", ""))
    if not command:
        return

    try:
        config = load_network_profiles()
    except PolicyError as exc:
        deny(str(exc))

    if config:
        profile_mode(command, config)
        return

    allowlist_mode(command)


if __name__ == "__main__":
    main()
