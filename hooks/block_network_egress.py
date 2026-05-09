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
    NetworkRequest,
    PolicyError,
    inspect_network_intent,
    iter_literal_commands,
    load_network_profiles,
    parse_codex_net_exec,
    split_segments,
    strip_wrappers,
    tokenize,
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


def auto_wrapped_command_text(nested_tokens: list[str]) -> str:
    nested = shlex.join(nested_tokens)
    wrapper = shlex.quote(str(WRAPPER_PATH))
    return f"{wrapper} autoexec -- {nested}".strip()


def first_request_issue(requests: list[NetworkRequest]) -> str | None:
    for request in requests:
        if request.issue:
            return str(request.issue)
    return None


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
                    validate_command_for_profile(
                        shlex.join(nested_tokens),
                        profile_name,
                        config,
                        enforce_require_approval=True,
                    )
                except PolicyError as exc:
                    deny(str(exc))
                continue

            segment_text = shlex.join(segment)
            intent = inspect_network_intent(config, segment_text)
            if not intent:
                continue

            issue = first_request_issue(intent.requests)
            if issue:
                deny(issue)

            if intent.kind == "implicit" and config["backend"] == "hook_only":
                deny(
                    f"This command implies network access and maps to profile `{intent.profile}`, but the hook_only backend "
                    "cannot verify its actual destination from the command text. Use a command with an explicit "
                    "remote target, keep it manual, or switch to linux_wsl_netns on stock WSL "
                    "(or another stronger backend that is ready on your host)."
                )

            suggested_profile = intent.profile or "<profile>"
            deny(
                "Direct network commands must use codex-net. "
                f"Retry as `{auto_wrapped_command_text(segment)}` or `{wrapped_command_text(suggested_profile, segment)}`."
            )


def main() -> None:
    payload = read_payload()
    command = str(payload.get("tool_input", {}).get("command", ""))
    if not command:
        return

    try:
        config = load_network_profiles()
    except PolicyError as exc:
        deny(str(exc))

    if not config:
        deny(
            "No network profile config was found. Install or create ~/.codex/policies/network_profiles.toml first. "
            "Profile-based network policy is required; the legacy network_allowlist.json path has been removed."
        )

    profile_mode(command, config)


if __name__ == "__main__":
    main()
