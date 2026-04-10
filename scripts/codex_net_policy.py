#!/usr/bin/env python3

import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.11+ has tomllib
    try:
        import tomli as tomllib
    except ModuleNotFoundError:  # pragma: no cover - optional fallback
        tomllib = None


DEFAULT_PROFILE_PATH = Path.home() / ".codex" / "policies" / "network_profiles.toml"
NETWORK_TOOLS = {"curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "rsync"}
INSPECTED_NETWORK_EXECUTABLES = NETWORK_TOOLS | {"git"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
SHELL_BOUNDARIES = {"&&", "||", ";", "|", "&"}
SHELL_WRAPPERS = {"ash", "bash", "dash", "fish", "ksh", "sh", "zsh"}
ENV_ASSIGNMENT_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
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
    "-P",
    "-Q",
    "-R",
    "-S",
    "-W",
    "-w",
}
ENV_OPTIONS_WITH_VALUES = {"-C", "--chdir", "-S", "-u", "--unset"}
DEFAULT_TOOL_PROFILES = {
    "curl": "registries",
    "wget": "registries",
    "ssh": "git_readonly",
    "scp": "git_readonly",
    "rsync": "git_readonly",
}
SCHEME_DEFAULT_PORTS = {"git": 9418, "http": 80, "https": 443, "rsync": 873, "ssh": 22}


class PolicyError(RuntimeError):
    pass


@dataclass
class NetworkRequest:
    tool: str
    target: str
    host: str | None
    port: int | None
    transport: str = "tcp"
    issue: str | None = None


@dataclass
class NetworkIntent:
    kind: str
    profile: str | None
    requests: list[NetworkRequest]


def profile_path() -> Path:
    override = os.environ.get("CODEX_NET_POLICY_PATH")
    return Path(override) if override else DEFAULT_PROFILE_PATH


def _string_map(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    normalized: dict[str, str] = {}
    for key, item in value.items():
        normalized[str(key).strip()] = str(item).strip()
    return {key: item for key, item in normalized.items() if key and item}


def _normalize_port_list(value: object) -> list[int]:
    if not isinstance(value, list):
        return []
    ports: list[int] = []
    for item in value:
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            ports.append(port)
    return sorted(set(ports))


def load_network_profiles(path: Path | None = None) -> dict | None:
    path = path or profile_path()
    if not path.exists():
        return None
    if tomllib is None:
        raise PolicyError(
            "Python 3.11+ or the `tomli` package is required to load network profile configs."
        )

    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PolicyError(f"Could not load network profile config {path}: {exc}") from exc

    profiles = {}
    raw_profiles = data.get("profiles", {})
    if not isinstance(raw_profiles, dict):
        raise PolicyError(f"Network profile config {path} has an invalid `profiles` section.")

    for name, raw_profile in raw_profiles.items():
        if not isinstance(raw_profile, dict):
            continue
        profile_name = str(name).strip()
        if not profile_name:
            continue
        allowed_domains = [
            str(item).strip().lower()
            for item in raw_profile.get("allowed_domains", [])
            if str(item).strip()
        ]
        profiles[profile_name] = {
            "description": str(raw_profile.get("description", "")).strip(),
            "allow_localhost": bool(raw_profile.get("allow_localhost", False)),
            "allowed_domains": sorted(set(allowed_domains)),
            "allowed_tcp_ports": _normalize_port_list(raw_profile.get("allowed_tcp_ports", [])),
            "allowed_udp_ports": _normalize_port_list(raw_profile.get("allowed_udp_ports", [])),
            "require_approval": bool(raw_profile.get("require_approval", False)),
        }

    if not profiles:
        raise PolicyError(f"Network profile config {path} does not define any usable profiles.")

    default_profile = str(data.get("default_profile", "")).strip() or "offline"
    if default_profile not in profiles:
        raise PolicyError(f"Network profile config {path} references unknown default profile `{default_profile}`.")

    tool_profiles = DEFAULT_TOOL_PROFILES | _string_map(data.get("tool_profiles", {}))
    command_profiles = _string_map(data.get("command_profiles", {}))

    return {
        "backend": str(data.get("backend", "hook_only")).strip() or "hook_only",
        "default_profile": default_profile,
        "command_profiles": command_profiles,
        "tool_profiles": tool_profiles,
        "backend_linux_wsl_nft": {
            "chain_name": str(data.get("backend_linux_wsl_nft", {}).get("chain_name", "codex_net_output")).strip()
            or "codex_net_output",
            "nft_table_name": str(data.get("backend_linux_wsl_nft", {}).get("nft_table_name", "codex_hardening")).strip()
            or "codex_hardening",
            "scope_unit_prefix": str(data.get("backend_linux_wsl_nft", {}).get("scope_unit_prefix", "codex-net")).strip()
            or "codex-net",
            "use_systemd_user": bool(data.get("backend_linux_wsl_nft", {}).get("use_systemd_user", True)),
        },
        "backend_linux_wsl_netns": {
            "namespace_prefix": str(data.get("backend_linux_wsl_netns", {}).get("namespace_prefix", "codex-net")).strip()
            or "codex-net",
            "host_veth_prefix": str(data.get("backend_linux_wsl_netns", {}).get("host_veth_prefix", "cnh")).strip()
            or "cnh",
            "guest_veth_prefix": str(data.get("backend_linux_wsl_netns", {}).get("guest_veth_prefix", "cng")).strip()
            or "cng",
            "nft_table_name": str(data.get("backend_linux_wsl_netns", {}).get("nft_table_name", "codex_netns_runtime")).strip()
            or "codex_netns_runtime",
        },
        "profiles": profiles,
        "path": path,
    }


def tokenize(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except Exception:
        return command.split()


def executable_name(token: str) -> str:
    return Path(token).name.lower()


def split_segments(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in SHELL_BOUNDARIES:
            if current:
                segments.append(current)
            current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    return segments


def is_env_assignment(token: str) -> bool:
    return bool(ENV_ASSIGNMENT_PATTERN.match(token))


def strip_wrappers(tokens: list[str]) -> tuple[str, list[str]] | None:
    index = 0
    while index < len(tokens) and is_env_assignment(tokens[index]):
        index += 1

    while index < len(tokens):
        name = executable_name(tokens[index])
        if name != "env":
            return name, tokens[index + 1 :]

        index += 1
        while index < len(tokens):
            token = tokens[index]
            if token == "--":
                index += 1
                break
            if is_env_assignment(token):
                index += 1
                continue
            if token in ENV_OPTIONS_WITH_VALUES:
                index += 2
                continue
            if token.startswith("--chdir=") or token.startswith("--unset="):
                index += 1
                continue
            if token.startswith("-"):
                index += 1
                continue
            break

    return None


def extract_shell_command(args: list[str]) -> str:
    for index, arg in enumerate(args):
        if arg in {"-c", "--command"} and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:] and index + 1 < len(args):
            return args[index + 1]
    return ""


def iter_literal_commands(command: str) -> list[str]:
    queue = [command]
    commands: list[str] = []
    seen = {command}

    while queue:
        current = queue.pop(0)
        commands.append(current)
        for segment in split_segments(tokenize(current)):
            resolved = strip_wrappers(segment)
            if not resolved:
                continue
            name, args = resolved
            if name not in SHELL_WRAPPERS:
                continue
            nested = extract_shell_command(args)
            if nested and nested not in seen:
                seen.add(nested)
                queue.append(nested)

    return commands


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


def parse_url_host_port(target: str) -> tuple[str | None, int | None]:
    if "://" in target:
        parsed = urlparse(target)
        host = (parsed.hostname or "").lower()
        port = parsed.port or SCHEME_DEFAULT_PORTS.get(parsed.scheme.lower())
        return host or None, port

    if target.startswith("[") and "]:" in target:
        host, _, tail = target[1:].partition("]:")
        return host.lower() or None, int(tail) if tail.isdigit() else None

    if target.count(":") == 1:
        host, _, tail = target.partition(":")
        if tail.isdigit():
            return host.lower() or None, int(tail)

    host = parse_host(target)
    return host or None, None


def looks_like_network_target(value: str) -> bool:
    return (
        "://" in value
        or "@" in value
        or value in LOCAL_HOSTS
        or (":" in value and not value.startswith("/") and not value.startswith("./") and not value.startswith("../"))
    )


def extract_option_port(args: list[str], names: set[str]) -> int | None:
    for index, arg in enumerate(args):
        if arg in names and index + 1 < len(args) and args[index + 1].isdigit():
            return int(args[index + 1])
        for name in names:
            if arg.startswith(name) and arg != name:
                suffix = arg[len(name) :]
                if suffix.isdigit():
                    return int(suffix)
    return None


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


def git_targets(args: list[str]) -> list[str]:
    index = 0
    while index < len(args) and args[index].startswith("-"):
        if args[index] in {"-c", "--config-env"} and index + 1 < len(args):
            index += 2
        else:
            index += 1

    if index >= len(args):
        return []

    subcommand = args[index]
    remainder = args[index + 1 :]
    if subcommand not in {"clone", "fetch", "ls-remote", "pull", "push"}:
        return []

    for arg in remainder:
        if arg.startswith("-"):
            continue
        if looks_like_network_target(arg):
            return [arg]
        if subcommand == "clone":
            break

    return []


def _request_with_issue(tool: str, issue: str, target: str = "") -> NetworkRequest:
    return NetworkRequest(tool=tool, target=target, host=None, port=None, issue=issue)


def _request_from_target(tool: str, target: str, port: int | None, transport: str = "tcp") -> NetworkRequest:
    if "$" in target:
        return _request_with_issue(tool, f"`{tool}` destination `{target}` is dynamic and cannot be verified.", target)

    host = parse_host(target)
    if not host:
        return _request_with_issue(tool, f"`{tool}` destination `{target}` could not be parsed.", target)

    return NetworkRequest(tool=tool, target=target, host=host, port=port, transport=transport)


def requests_for_segment(tool: str, args: list[str]) -> list[NetworkRequest]:
    if tool in {"curl", "wget"}:
        targets = curl_wget_targets(args)
        if not targets:
            return [_request_with_issue(tool, f"`{tool}` has no identifiable destination to verify.")]
        return [
            _request_from_target(tool, target, parse_url_host_port(target)[1])
            for target in targets
        ]

    if tool == "ssh":
        targets = ssh_targets(args)
        if not targets:
            return [_request_with_issue(tool, f"`{tool}` has no identifiable destination to verify.")]
        port = extract_option_port(args, {"-p"}) or 22
        return [_request_from_target(tool, target, port) for target in targets]

    if tool in {"scp", "rsync"}:
        targets = scp_rsync_targets(args)
        if not targets:
            return [_request_with_issue(tool, f"`{tool}` has no identifiable destination to verify.")]
        requests = []
        default_port = extract_option_port(args, {"-P", "-p"}) or 22
        for target in targets:
            port = default_port
            if tool == "rsync" and target.startswith("rsync://"):
                _, parsed_port = parse_url_host_port(target)
                port = parsed_port or 873
            elif tool == "rsync" and "::" in target:
                port = 873
            requests.append(_request_from_target(tool, target, port))
        return requests

    if tool in {"nc", "ncat", "netcat"}:
        targets = netcat_targets(args)
        if not targets:
            return [_request_with_issue(tool, f"`{tool}` with no identifiable target is blocked.")]
        host_target = targets[0]
        port = None
        if len(targets) > 1 and targets[1].isdigit():
            port = int(targets[1])
        transport = "udp" if "-u" in args else "tcp"
        return [_request_from_target(tool, host_target, port, transport=transport)]

    targets = git_targets(args)
    if not targets:
        return []

    requests = []
    for target in targets:
        host, port = parse_url_host_port(target)
        if "://" in target and port is None:
            parsed = urlparse(target)
            port = SCHEME_DEFAULT_PORTS.get(parsed.scheme.lower())
        if "@" in target and port is None:
            port = 22
        requests.append(
            _request_from_target(
                tool,
                target,
                port,
            )
        )
    return requests


def collect_network_requests(command: str) -> list[NetworkRequest]:
    requests: list[NetworkRequest] = []
    for candidate in iter_literal_commands(command):
        for segment in split_segments(tokenize(candidate)):
            resolved = strip_wrappers(segment)
            if not resolved:
                continue
            tool, args = resolved
            if tool in INSPECTED_NETWORK_EXECUTABLES:
                requests.extend(requests_for_segment(tool, args))
    return requests


def host_is_allowed(host: str, allowed_domains: list[str] | set[str]) -> bool:
    normalized = host.strip().lower().rstrip(".")
    if not normalized:
        return False
    if normalized in LOCAL_HOSTS:
        return True
    return any(
        normalized == domain or normalized.endswith(f".{domain}")
        for domain in allowed_domains
    )


def parse_codex_net_exec(args: list[str], default_profile: str) -> tuple[str, list[str]] | None:
    if not args or args[0] != "exec":
        return None

    profile = default_profile
    nested: list[str] = []
    index = 1
    while index < len(args):
        arg = args[index]
        if arg == "--":
            nested = args[index + 1 :]
            break
        if arg == "--profile" and index + 1 < len(args):
            profile = args[index + 1]
            index += 2
            continue
        if arg.startswith("--profile="):
            profile = arg.split("=", 1)[1]
            index += 1
            continue
        index += 1

    return profile, nested


def mapped_profile_for_command(config: dict, command: str) -> str | None:
    for candidate in iter_literal_commands(command):
        tokens = tokenize(candidate)
        if not tokens:
            continue
        for mapping, profile in sorted(
            config["command_profiles"].items(),
            key=lambda item: len(tokenize(item[0])),
            reverse=True,
        ):
            prefix = tokenize(mapping)
            if tokens[: len(prefix)] == prefix and profile in config["profiles"]:
                return profile

        for segment in split_segments(tokens):
            resolved = strip_wrappers(segment)
            if not resolved:
                continue
            name, _ = resolved
            profile = config["tool_profiles"].get(name)
            if profile in config["profiles"]:
                return profile

    return None


def select_profile_for_command(config: dict, command: str) -> str | None:
    mapped = mapped_profile_for_command(config, command)
    if mapped:
        return mapped

    # Only fall back to `custom` when the command already contains an
    # explicit network target that the hook can inspect. Returning `custom`
    # for every unmatched command causes ordinary shell commands like `ls`
    # to be misclassified as networked.
    if "custom" in config["profiles"] and collect_network_requests(command):
        return "custom"
    return None


def inspect_network_intent(config: dict, command: str) -> NetworkIntent | None:
    requests = collect_network_requests(command)
    profile = select_profile_for_command(config, command)

    if requests:
        return NetworkIntent(kind="explicit", profile=profile, requests=requests)
    if profile:
        return NetworkIntent(kind="implicit", profile=profile, requests=[])
    return None


def _validate_request_against_profile(request: NetworkRequest, profile_name: str, config: dict) -> None:
    if request.issue:
        raise PolicyError(request.issue)

    if not request.host:
        raise PolicyError(f"`{request.tool}` destination `{request.target}` could not be parsed.")

    profile = config["profiles"][profile_name]
    is_local = request.host in LOCAL_HOSTS
    allowed_ports = profile["allowed_tcp_ports"] if request.transport == "tcp" else profile["allowed_udp_ports"]

    if is_local:
        if not profile["allow_localhost"]:
            raise PolicyError(f"Profile `{profile_name}` does not allow localhost network access.")
        if allowed_ports and request.port is not None and request.port not in allowed_ports:
            raise PolicyError(
                f"Profile `{profile_name}` does not allow localhost {request.transport.upper()} port {request.port}."
            )
        return

    if not host_is_allowed(request.host, profile["allowed_domains"]):
        raise PolicyError(
            f"Profile `{profile_name}` does not allow `{request.tool}` destination `{request.target}`."
        )

    if not allowed_ports:
        raise PolicyError(
            f"Profile `{profile_name}` does not allow remote {request.transport.upper()} network access."
        )

    if request.port is None:
        raise PolicyError(
            f"Profile `{profile_name}` could not verify a port for `{request.tool}` destination `{request.target}`."
        )

    if request.port not in allowed_ports:
        raise PolicyError(
            f"Profile `{profile_name}` does not allow {request.transport.upper()} port {request.port} "
            f"for `{request.tool}` destination `{request.target}`."
        )


def validate_command_for_profile(command: str, profile_name: str, config: dict) -> None:
    if profile_name not in config["profiles"]:
        raise PolicyError(f"Unknown network profile `{profile_name}`.")

    intent = inspect_network_intent(config, command)
    requests = intent.requests if intent else []

    if config["backend"] == "hook_only" and intent and intent.kind == "implicit":
        raise PolicyError(
            "The hook_only backend can only validate commands with explicit network targets in the command text. "
            "This command needs a manual operator decision today, or a stronger backend on a host that supports it."
        )

    for request in requests:
        _validate_request_against_profile(request, profile_name, config)
