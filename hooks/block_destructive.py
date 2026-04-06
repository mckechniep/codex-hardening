#!/usr/bin/env python3

import json
import re
import sys


HARD_BLOCK_PATTERNS = [
    (
        re.compile(r"\brm\s+-[^\n;&|]*[rf][^\n;&|]*\s+(?:--no-preserve-root\s+)?/(?:\s|$)"),
        "Recursive deletion at filesystem root is never allowed for Codex.",
    ),
    (
        re.compile(r"\brm\s+-[^\n;&|]*[rf][^\n;&|]*\s+~(?:/|\s|$)"),
        "Recursive deletion in the home directory is never allowed for Codex.",
    ),
    (
        re.compile(r"\bmkfs(?:\.[a-z0-9_+-]+)?\b"),
        "Filesystem formatting commands are never allowed for Codex.",
    ),
    (
        re.compile(r"\bdd\b[^\n;&|]*\bif="),
        "Raw disk copy commands are never allowed for Codex.",
    ),
    (
        re.compile(r"\bshred\b"),
        "Data shredding commands are never allowed for Codex.",
    ),
    (
        re.compile(r"\bwipefs\b"),
        "Filesystem wipe commands are never allowed for Codex.",
    ),
    (
        re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:"),
        "Fork bomb patterns are never allowed for Codex.",
    ),
    (
        re.compile(r">\s*/dev/(?:sd[a-z]\d*|vd[a-z]\d*|nvme\d+n\d+(?:p\d+)?)"),
        "Direct device overwrites are never allowed for Codex.",
    ),
]

MANUAL_ONLY_PATTERNS = [
    (re.compile(r"\bsudo\b"), "Privilege escalation is manual-only."),
    (
        re.compile(r"\bgit\s+push\b[^\n;&|]*\s--force(?:-with-lease)?\b|\bgit\s+push\s+--force(?:-with-lease)?\b"),
        "Force-pushing Git history is manual-only.",
    ),
    (
        re.compile(r"\bgit\s+reset\s+--hard\b"),
        "Destructive Git resets are manual-only.",
    ),
    (
        re.compile(r"\bgit\s+clean\b[^\n;&|]*\s-f(?:[a-z]*)?\b"),
        "Destructive Git clean operations are manual-only.",
    ),
    (
        re.compile(r"\bgit\s+checkout\s+--\s+\."),
        "Discarding tracked changes is manual-only.",
    ),
    (
        re.compile(r"\bchmod\s+777\b"),
        "Dangerous permission changes are manual-only.",
    ),
    (
        re.compile(r"\bkill\s+-9\b"),
        "Force-killing processes is manual-only.",
    ),
    (
        re.compile(r"\bkillall\b"),
        "Killing processes by name is manual-only.",
    ),
    (
        re.compile(r"\breboot\b"),
        "System reboot commands are manual-only.",
    ),
    (
        re.compile(r"\bshutdown\b"),
        "System shutdown commands are manual-only.",
    ),
    (
        re.compile(r"\bsystemctl\s+stop\b"),
        "Stopping system services is manual-only.",
    ),
]


def read_command() -> str:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return ""
    return str(payload.get("tool_input", {}).get("command", ""))


def deny(message: str) -> None:
    sys.stderr.write(
        f"Blocked by ~/.codex/hooks/block_destructive.py: {message} "
        "If you intend this, run it yourself outside Codex.\n"
    )
    raise SystemExit(2)


def main() -> None:
    command = read_command()
    if not command:
        return

    normalized = " ".join(command.lower().split())

    for pattern, message in HARD_BLOCK_PATTERNS:
        if pattern.search(normalized):
            deny(message)

    for pattern, message in MANUAL_ONLY_PATTERNS:
        if pattern.search(normalized):
            deny(message)


if __name__ == "__main__":
    main()
