#!/usr/bin/env python3

import json
import shlex
import sys
from pathlib import Path
from urllib.parse import urlparse


ALLOWLIST_PATH = Path.home() / ".codex" / "policies" / "network_allowlist.json"
NETWORK_TOOLS = {"curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "rsync"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
SHELL_BOUNDARIES = {"&&", "||", ";", "|", "&"}
CURL_WGET_OPTIONS_WITH_VALUES = {
    "-o",
    "--output",
    "-O",
    "-H",
    "--header",
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--json",
    "-u",
    "--user",
    "-A",
    "--user-agent",
    "-e",
    "--referer",
    "-b",
    "--cookie",
    "-F",
    "--form",
    "--proxy",
    "-x",
    "--request",
    "-X",
    "--config",
    "--interface",
    "--resolve",
    "--connect-to",
    "--cacert",
    "--cert",
    "--key",
    "--url",
}
SSH_OPTIONS_WITH_VALUES = {
    "-b",
    "-c",
    "-D",
    "-E",
    "-e",
    "-F",
    "-I",
    "-i",
    "-J",
    "-L",
    "-l",
    "-m",
    "-O",
    "-o",
    "-p",
    "-Q",
    "-R",
    "-S",
    "-W",
    "-w",
}


def read_payload() -> dict:
    try:
        return json.load(sys.stdin)
    except Exception:
        return {}


def load_allowlist() -> set[str]:
    try:
        data = json.loads(ALLOWLIST_PATH.read_text())
    except Exception:
        return set(LOCAL_HOSTS)
    domains = {str(item).strip().lower() for item in data.get("allowed_domains", []) if str(item).strip()}
    return domains | LOCAL_HOSTS


def tokenize(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except Exception:
        return command.split()


def host_is_allowed(host: str, allowlist: set[str]) -> bool:
    host = host.strip().lower().rstrip(".")
    if not host:
        return False
    if host in LOCAL_HOSTS:
        return True
    return any(host == domain or host.endswith(f".{domain}") for domain in allowlist)


def parse_host(candidate: str) -> str:
    value = candidate.strip()
    if not value:
        return ""
    if "://" in value:
        return (urlparse(value).hostname or "").lower()
    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")].lower()
    if "@" in value and ":" in value:
        return value.split("@", 1)[1].split(":", 1)[0].lower()
    if "@" in value:
        return value.split("@", 1)[1].lower()
    if ":" in value and not value.startswith("/"):
        return value.split(":", 1)[0].lower()
    return value.lower()


def collect_segments(tokens: list[str]) -> list[tuple[str, list[str]]]:
    segments = []
    current_tool = None
    current_args: list[str] = []
    for token in tokens:
        if token in SHELL_BOUNDARIES:
            if current_tool:
                segments.append((current_tool, current_args))
            current_tool = None
            current_args = []
            continue
        if token in NETWORK_TOOLS:
            if current_tool:
                segments.append((current_tool, current_args))
            current_tool = token
            current_args = []
            continue
        if current_tool:
            current_args.append(token)
    if current_tool:
        segments.append((current_tool, current_args))
    return segments


def iter_non_option_args(args: list[str], options_with_values: set[str]) -> list[str]:
    values = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in SHELL_BOUNDARIES:
            break
        if arg in options_with_values:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        values.append(arg)
    return values


def curl_wget_targets(args: list[str]) -> list[str]:
    return [
        arg
        for arg in iter_non_option_args(args, CURL_WGET_OPTIONS_WITH_VALUES)
        if "://" in arg or arg.startswith("$") or "${" in arg or "$(" in arg or "." in arg or ":" in arg
    ]


def ssh_targets(args: list[str]) -> list[str]:
    targets = []
    for arg in iter_non_option_args(args, SSH_OPTIONS_WITH_VALUES):
        if "@" in arg or "." in arg or arg in LOCAL_HOSTS or arg.startswith("$") or "${" in arg or "$(" in arg:
            targets.append(arg)
            break
    return targets


def scp_rsync_targets(args: list[str]) -> list[str]:
    return [
        arg
        for arg in iter_non_option_args(args, SSH_OPTIONS_WITH_VALUES)
        if "://" in arg or "@" in arg or (":" in arg and not arg.startswith("/")) or arg.startswith("$") or "${" in arg or "$(" in arg
    ]


def netcat_targets(args: list[str]) -> list[str]:
    targets = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in {"-p", "-s", "-w", "-i", "-l", "-k", "-u", "-U", "-x", "-X"}:
            if arg in {"-p", "-s", "-w", "-i", "-x", "-X"}:
                skip_next = True
            continue
        if arg.startswith("-"):
            continue
        targets.append(arg)
    return targets


def deny(message: str) -> None:
    sys.stderr.write(
        f"Blocked by ~/.codex/hooks/block_network_egress.py: {message} "
        "If you intend this network action, run it yourself outside Codex or update "
        "~/.codex/policies/network_allowlist.json first.\n"
    )
    raise SystemExit(2)


def validate_segment(tool: str, args: list[str], allowlist: set[str]) -> None:
    if tool in {"nc", "ncat", "netcat"}:
        targets = netcat_targets(args)
        if not targets:
            deny(f"`{tool}` with no identifiable target is blocked.")
        host = parse_host(targets[0])
        if not host or not host_is_allowed(host, allowlist):
            deny(f"`{tool}` target `{targets[0]}` is not on the allowlist.")
        return

    if tool in {"curl", "wget"}:
        targets = curl_wget_targets(args)
    elif tool == "ssh":
        targets = ssh_targets(args)
    else:
        targets = scp_rsync_targets(args)

    if not targets:
        deny(f"`{tool}` has no identifiable destination to verify.")

    for target in targets:
        if "$" in target:
            deny(f"`{tool}` destination `{target}` is dynamic and cannot be verified.")
        host = parse_host(target)
        if not host:
            deny(f"`{tool}` destination `{target}` could not be parsed.")
        if not host_is_allowed(host, allowlist):
            deny(f"`{tool}` destination `{target}` is not on the allowlist.")


def main() -> None:
    payload = read_payload()
    command = str(payload.get("tool_input", {}).get("command", ""))
    if not command:
        return

    tokens = tokenize(command)
    if not any(token in NETWORK_TOOLS for token in tokens):
        return

    allowlist = load_allowlist()
    for tool, args in collect_segments(tokens):
        validate_segment(tool, args, allowlist)


if __name__ == "__main__":
    main()
