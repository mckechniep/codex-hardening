#!/usr/bin/env python3

import gzip
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from hashlib import sha256
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_COMPILED_DIR = Path.home() / ".codex" / "state" / "codex-net"
DEFAULT_STATE_PATH = DEFAULT_COMPILED_DIR / "backend_state.json"
DEFAULT_USER_UNIT_DIR = Path.home() / ".config" / "systemd" / "user"
SYSTEM_UNIT_DIR = Path("/etc/systemd/system")


class BackendError(RuntimeError):
    pass


def compiled_dir() -> Path:
    override = os.environ.get("CODEX_NET_COMPILED_DIR")
    return Path(override) if override else DEFAULT_COMPILED_DIR


def state_path() -> Path:
    override = os.environ.get("CODEX_NET_STATE_PATH")
    return Path(override) if override else DEFAULT_STATE_PATH


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return ""


def _kernel_config_value(symbol: str) -> str | None:
    release = _read_text("/proc/sys/kernel/osrelease")
    candidates = [
        Path("/proc/config.gz"),
        Path(f"/boot/config-{release}") if release else None,
    ]
    prefix = f"{symbol}="
    disabled = f"# {symbol} is not set"

    for candidate in candidates:
        if not candidate or not candidate.exists():
            continue
        try:
            if candidate.name.endswith(".gz"):
                with gzip.open(candidate, "rt") as handle:
                    lines = handle.readlines()
            else:
                lines = candidate.read_text().splitlines()
        except OSError:
            continue

        for line in lines:
            stripped = line.strip()
            if stripped.startswith(prefix):
                return stripped.split("=", 1)[1]
            if stripped == disabled:
                return "n"
    return None


def nft_socket_support_report() -> dict[str, str | bool]:
    config_value = _kernel_config_value("CONFIG_NFT_SOCKET")
    if config_value in {"y", "m"}:
        return {
            "ok": True,
            "config_value": config_value,
            "detail": f"CONFIG_NFT_SOCKET={config_value}",
        }
    if config_value == "n":
        return {
            "ok": False,
            "config_value": config_value,
            "detail": "CONFIG_NFT_SOCKET is not set in this kernel.",
        }
    return {
        "ok": False,
        "config_value": "unknown",
        "detail": "Could not determine whether CONFIG_NFT_SOCKET is enabled in this kernel.",
    }


def detect_environment() -> dict[str, str]:
    osrelease = _read_text("/proc/sys/kernel/osrelease")
    version = _read_text("/proc/version")
    combined = f"{osrelease}\n{version}".lower()
    return {
        "platform": sys.platform,
        "osrelease": osrelease,
        "version": version,
        "is_linux": "true" if sys.platform.startswith("linux") else "false",
        "is_wsl": "true" if "microsoft" in combined or "wsl" in combined else "false",
        "is_wsl2": "true" if "wsl2" in combined else "false",
    }


def capability_checks() -> list[dict[str, str]]:
    env = detect_environment()
    nft_socket_report = nft_socket_support_report()
    user_scope_report = default_scope_runtime_report()
    system_scope_report = system_scope_runtime_report()
    checks = [
        {
            "name": "linux",
            "required": "true",
            "ok": env["is_linux"],
            "detail": "Linux is required for the WSL nftables backend.",
        },
        {
            "name": "wsl2",
            "required": "true",
            "ok": env["is_wsl2"],
            "detail": "WSL 2 is the supported first-pass target.",
        },
        {
            "name": "nft",
            "required": "true",
            "ok": "true" if shutil.which("nft") else "false",
            "detail": "The `nft` command must be installed for nftables-backed enforcement.",
        },
        {
            "name": "nft_socket_expr",
            "required": "true",
            "ok": "true" if nft_socket_report["ok"] else "false",
            "detail": (
                "The kernel must enable CONFIG_NFT_SOCKET for `socket cgroupv2` matching. "
                + str(nft_socket_report["detail"])
            ),
        },
        {
            "name": "sudo",
            "required": "true",
            "ok": "true" if shutil.which("sudo") else "false",
            "detail": "Privileged setup uses `sudo`.",
        },
        {
            "name": "cgroup_v2",
            "required": "true",
            "ok": "true" if Path("/sys/fs/cgroup/cgroup.controllers").exists() else "false",
            "detail": "cgroup v2 is needed for the planned packet-to-command binding.",
        },
        {
            "name": "systemd",
            "required": "false",
            "ok": "true" if Path("/run/systemd/system").exists() else "false",
            "detail": "Systemd is recommended for delegated scopes and refresh tasks.",
        },
        {
            "name": "systemd_user_manager",
            "required": "false",
            "ok": "true" if user_scope_report["ok"] else "false",
            "detail": str(user_scope_report["detail"]),
        },
        {
            "name": "systemd_system_manager",
            "required": "false",
            "ok": "true" if system_scope_report["ok"] else "false",
            "detail": str(system_scope_report["detail"]),
        },
    ]
    return checks


def resolver_addresses() -> dict[str, list[str]]:
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    try:
        lines = Path("/etc/resolv.conf").read_text().splitlines()
    except OSError:
        return {"ipv4": [], "ipv6": []}

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) != 2 or fields[0] != "nameserver":
            continue
        address = fields[1]
        try:
            socket.inet_pton(socket.AF_INET, address)
            ipv4.add(address)
            continue
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, address)
            ipv6.add(address)
        except OSError:
            continue

    return {"ipv4": sorted(ipv4), "ipv6": sorted(ipv6)}


def doctor_report() -> dict:
    env = detect_environment()
    checks = capability_checks()
    required_ok = all(item["ok"] == "true" for item in checks if item["required"] == "true")
    recommended_missing = [item["name"] for item in checks if item["required"] == "false" and item["ok"] != "true"]
    return {
        "environment": env,
        "checks": checks,
        "resolvers": resolver_addresses(),
        "ready": required_ok,
        "recommended_missing": recommended_missing,
    }


def _resolve_domain(domain: str) -> dict[str, list[str] | str]:
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    error = ""

    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        infos = []
        error = str(exc)

    for family, _, _, _, sockaddr in infos:
        address = sockaddr[0]
        if family == socket.AF_INET:
            ipv4.add(address)
        elif family == socket.AF_INET6:
            ipv6.add(address)

    return {
        "ipv4": sorted(ipv4),
        "ipv6": sorted(ipv6),
        "error": error,
    }


def _profile_set_name(profile_name: str, suffix: str) -> str:
    cleaned = "".join(ch if ch.isalnum() else "_" for ch in profile_name.lower()).strip("_")
    cleaned = cleaned or "profile"
    return f"{cleaned}_{suffix}"


def _profile_unit_token(profile_name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() else "-" for ch in profile_name.lower()).strip("-")
    return cleaned or "profile"


def _slice_mode(config: dict) -> str:
    return "systemd_user" if config["backend_linux_wsl_nft"]["use_systemd_user"] else "systemd_system"


def _slice_cgroup_components(slice_name: str, mode: str, uid: int | None = None) -> list[str]:
    if not slice_name.endswith(".slice"):
        raise BackendError(f"Invalid slice unit name `{slice_name}`.")

    stem = slice_name[:-6]
    parts = [part for part in stem.split("-") if part]
    if not parts:
        raise BackendError(f"Invalid slice unit name `{slice_name}`.")

    hierarchy = ["-".join(parts[:index]) + ".slice" for index in range(1, len(parts) + 1)]
    if mode == "systemd_user":
        uid = os.getuid() if uid is None else uid
        return [
            "user.slice",
            f"user-{uid}.slice",
            f"user@{uid}.service",
            *hierarchy,
        ]
    return hierarchy


def _slice_cgroup_match_level(slice_name: str, mode: str, uid: int | None = None) -> int:
    return len(_slice_cgroup_components(slice_name, mode, uid=uid))


def compile_profiles(config: dict, output_dir: Path | None = None) -> dict:
    output_dir = output_dir or compiled_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "backend": config["backend"],
        "backend_linux_wsl_nft": config.get("backend_linux_wsl_nft", {}),
        "default_profile": config["default_profile"],
        "resolvers": resolver_addresses(),
        "source_path": str(config["path"]),
        "profiles": {},
    }
    resolved_domain_count = 0
    unresolved_domain_count = 0

    for profile_name, profile in sorted(config["profiles"].items()):
        resolutions = {}
        ipv4: set[str] = set()
        ipv6: set[str] = set()
        for domain in profile["allowed_domains"]:
            result = _resolve_domain(domain)
            resolutions[domain] = result
            if result["ipv4"] or result["ipv6"]:
                resolved_domain_count += 1
            else:
                unresolved_domain_count += 1
            ipv4.update(result["ipv4"])
            ipv6.update(result["ipv6"])

        manifest["profiles"][profile_name] = {
            "description": profile["description"],
            "allow_localhost": profile["allow_localhost"],
            "allowed_domains": profile["allowed_domains"],
            "allowed_tcp_ports": profile["allowed_tcp_ports"],
            "allowed_udp_ports": profile["allowed_udp_ports"],
            "require_approval": profile["require_approval"],
            "resolved_ipv4": sorted(ipv4),
            "resolved_ipv6": sorted(ipv6),
            "resolutions": resolutions,
            "set_names": {
                "ipv4": _profile_set_name(profile_name, "ipv4"),
                "ipv6": _profile_set_name(profile_name, "ipv6"),
                "tcp_ports": _profile_set_name(profile_name, "tcp_ports"),
                "udp_ports": _profile_set_name(profile_name, "udp_ports"),
            },
            "runtime_units": {
                "scope_unit": scope_unit_name(profile_name, config),
                "slice_unit": slice_unit_name(profile_name, config, _slice_mode(config)),
                "mode": _slice_mode(config),
                "cgroup_match_level": _slice_cgroup_match_level(
                    slice_unit_name(profile_name, config, _slice_mode(config)),
                    _slice_mode(config),
                ),
                "cgroup_path": "/".join(
                    _slice_cgroup_components(
                        slice_unit_name(profile_name, config, _slice_mode(config)),
                        _slice_mode(config),
                    )
                ),
            },
        }

    json_path = output_dir / "network_profiles.compiled.json"
    nft_path = output_dir / "network_profiles.compiled.nft"
    json_path.write_text(json.dumps(manifest, indent=2) + "\n")
    nft_path.write_text(render_nftables_rules(manifest))
    nft_hash = sha256(nft_path.read_bytes()).hexdigest()

    return {
        "output_dir": str(output_dir),
        "json_path": str(json_path),
        "nft_path": str(nft_path),
        "nft_sha256": nft_hash,
        "profile_count": len(manifest["profiles"]),
        "resolved_domain_count": resolved_domain_count,
        "unresolved_domain_count": unresolved_domain_count,
        "manifest": manifest,
    }


def _render_set_block(name: str, set_type: str, elements: list[str], interval: bool = False) -> list[str]:
    lines = [f"    set {name} {{", f"        type {set_type}"]
    if interval:
        lines.append("        flags interval")
    if elements:
        rendered = ", ".join(elements)
        lines.append(f"        elements = {{ {rendered} }}")
    lines.append("    }")
    return lines


def _scope_unit_name(prefix: str, profile_name: str) -> str:
    return f"{prefix}-{_profile_unit_token(profile_name)}.scope"


def _anchor_unit_name(prefix: str, profile_name: str) -> str:
    return f"{prefix}-anchor-{_profile_unit_token(profile_name)}.service"


def _slice_unit_name(prefix: str, profile_name: str, mode: str) -> str:
    token = _profile_unit_token(profile_name)
    if mode == "systemd_user":
        return f"app-{prefix}-{token}.slice"
    return f"system-{prefix}-{token}.slice"


def table_name(config: dict) -> str:
    return config["backend_linux_wsl_nft"]["nft_table_name"]


def scope_unit_name(profile_name: str, config: dict) -> str:
    return _scope_unit_name(config["backend_linux_wsl_nft"]["scope_unit_prefix"], profile_name)


def anchor_unit_name(profile_name: str, config: dict) -> str:
    return _anchor_unit_name(config["backend_linux_wsl_nft"]["scope_unit_prefix"], profile_name)


def slice_unit_name(profile_name: str, config: dict, mode: str) -> str:
    return _slice_unit_name(config["backend_linux_wsl_nft"]["scope_unit_prefix"], profile_name, mode)


def scope_launch_command(
    profile_name: str,
    wrapped_command: list[str],
    config: dict,
    mode: str | None = None,
) -> list[str]:
    if mode is None:
        mode = "systemd_user" if config["backend_linux_wsl_nft"]["use_systemd_user"] else "systemd_system"
    use_systemd_user = mode == "systemd_user"
    command = [
        "systemd-run",
        *(["--user"] if use_systemd_user else []),
        "--scope",
        f"--unit={scope_unit_name(profile_name, config)}",
        f"--slice={slice_unit_name(profile_name, config, mode)}",
        "--same-dir",
        *wrapped_command,
    ]
    if not use_systemd_user:
        command.insert(0, "sudo")
    return command


def _run_probe(command: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        return False, f"`{command[0]}` is not installed."
    except subprocess.TimeoutExpired:
        return False, f"`{' '.join(command)}` timed out."

    detail = (result.stderr or result.stdout).strip()
    if result.returncode == 0:
        return True, detail or "ok"
    return False, detail or f"`{' '.join(command)}` exited with code {result.returncode}."


def default_scope_runtime_report() -> dict[str, str | bool]:
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    if not shutil.which("systemd-run"):
        return {
            "ok": False,
            "mode": "systemd_user",
            "runtime_dir": runtime_dir,
            "detail": "The `systemd-run` command is required for profile-bound execution.",
        }
    if not Path(runtime_dir).exists():
        return {
            "ok": False,
            "mode": "systemd_user",
            "runtime_dir": runtime_dir,
            "detail": (
                f"`{runtime_dir}` does not exist. Enable systemd in WSL with `[boot] systemd=true`, "
                "restart the distro, and try again."
            ),
        }
    ok, detail = _run_probe(["systemctl", "--user", "show-environment"])
    return {
        "ok": ok,
        "mode": "systemd_user",
        "runtime_dir": runtime_dir,
        "detail": (
            detail
            if ok
            else (
                "The user systemd manager is not reachable. Enable systemd in WSL with `[boot] systemd=true`, "
                f"restart the distro, and try again. Probe detail: {detail}"
            )
        ),
    }


def system_scope_runtime_report() -> dict[str, str | bool]:
    if not shutil.which("systemd-run"):
        return {
            "ok": False,
            "mode": "systemd_system",
            "detail": "The `systemd-run` command is required for profile-bound execution.",
        }
    if not shutil.which("sudo"):
        return {
            "ok": False,
            "mode": "systemd_system",
            "detail": "`sudo` is required when `use_systemd_user = false`.",
        }
    ok, detail = _run_probe(["systemctl", "show-environment"])
    return {
        "ok": ok,
        "mode": "systemd_system",
        "detail": detail if ok else f"The system systemd manager is not reachable. Probe detail: {detail}",
    }


def scope_runtime_report(config: dict) -> dict[str, str | bool]:
    backend = config["backend_linux_wsl_nft"]
    prefer_user_scope = backend["use_systemd_user"]

    if prefer_user_scope:
        user_report = default_scope_runtime_report()
        if user_report["ok"]:
            return {
                **user_report,
                "selected_mode": "systemd_user",
                "fallback_used": False,
            }
        return {
            **user_report,
            "selected_mode": "systemd_user",
            "fallback_used": False,
        }

    system_report = system_scope_runtime_report()
    return {
        **system_report,
        "selected_mode": "systemd_system",
        "fallback_used": False,
    }


def render_nftables_rules(manifest: dict) -> str:
    backend = manifest.get("backend_linux_wsl_nft", {})
    table_name = backend.get("nft_table_name", "codex_hardening")
    chain_name = backend.get("chain_name", "codex_net_output")
    resolvers = manifest.get("resolvers", {"ipv4": [], "ipv6": []})

    lines = [
        "# Generated by codex-net compile-profiles",
        "# Intended for the linux_wsl_nft backend.",
        "# Review before applying with nft -f.",
        f"# Source policy: {manifest['source_path']}",
        "",
        f"table inet {table_name} {{",
    ]

    if resolvers["ipv4"]:
        lines.extend(_render_set_block("resolver_ipv4", "ipv4_addr", resolvers["ipv4"], interval=True))
    if resolvers["ipv6"]:
        lines.extend(_render_set_block("resolver_ipv6", "ipv6_addr", resolvers["ipv6"], interval=True))
    if resolvers["ipv4"] or resolvers["ipv6"]:
        lines.append("")

    for profile_name, profile in sorted(manifest["profiles"].items()):
        lines.append(f"    # Profile: {profile_name}")
        lines.extend(_render_set_block(profile["set_names"]["ipv4"], "ipv4_addr", profile["resolved_ipv4"], interval=True))
        lines.extend(_render_set_block(profile["set_names"]["ipv6"], "ipv6_addr", profile["resolved_ipv6"], interval=True))
        lines.extend(
            _render_set_block(
                profile["set_names"]["tcp_ports"],
                "inet_service",
                [str(port) for port in profile["allowed_tcp_ports"]],
            )
        )
        lines.extend(
            _render_set_block(
                profile["set_names"]["udp_ports"],
                "inet_service",
                [str(port) for port in profile["allowed_udp_ports"]],
            )
        )
        lines.append("")

    lines.extend(
        [
            f"    chain {chain_name} {{",
            "        type filter hook output priority filter; policy accept;",
        ]
    )

    for profile_name, profile in sorted(manifest["profiles"].items()):
        slice_name = profile["runtime_units"]["slice_unit"]
        cgroup_level = int(profile["runtime_units"]["cgroup_match_level"])
        cgroup_path = str(profile["runtime_units"].get("cgroup_path") or slice_name)
        cgroup_match = f'socket cgroupv2 level {cgroup_level} "{cgroup_path}"'
        lines.append(f"        # Slice: {slice_name}")

        if profile["allow_localhost"]:
            lines.append(f'        {cgroup_match} oifname "lo" accept')

        if profile["allowed_udp_ports"] and resolvers["ipv4"]:
            lines.append(
                f"        {cgroup_match} ip daddr @resolver_ipv4 udp dport @"
                f"{profile['set_names']['udp_ports']} accept"
            )
        if profile["allowed_udp_ports"] and resolvers["ipv6"]:
            lines.append(
                f"        {cgroup_match} ip6 daddr @resolver_ipv6 udp dport @"
                f"{profile['set_names']['udp_ports']} accept"
            )
        if 53 in profile["allowed_tcp_ports"] and resolvers["ipv4"]:
            lines.append(
                f"        {cgroup_match} ip daddr @resolver_ipv4 tcp dport 53 accept"
            )
        if 53 in profile["allowed_tcp_ports"] and resolvers["ipv6"]:
            lines.append(
                f"        {cgroup_match} ip6 daddr @resolver_ipv6 tcp dport 53 accept"
            )

        if profile["allowed_tcp_ports"]:
            lines.append(
                f"        {cgroup_match} ip daddr @{profile['set_names']['ipv4']} tcp dport @"
                f"{profile['set_names']['tcp_ports']} accept"
            )
            lines.append(
                f"        {cgroup_match} ip6 daddr @{profile['set_names']['ipv6']} tcp dport @"
                f"{profile['set_names']['tcp_ports']} accept"
            )
        if profile["allowed_udp_ports"]:
            lines.append(
                f"        {cgroup_match} ip daddr @{profile['set_names']['ipv4']} udp dport @"
                f"{profile['set_names']['udp_ports']} accept"
            )
            lines.append(
                f"        {cgroup_match} ip6 daddr @{profile['set_names']['ipv6']} udp dport @"
                f"{profile['set_names']['udp_ports']} accept"
            )

        lines.append(f"        {cgroup_match} reject with icmpx admin-prohibited")
        lines.append("")

    if lines[-1] == "":
        lines.pop()
    lines.append("    }")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def write_backend_state(compiled: dict | None, applied: bool, extra: dict | None = None) -> dict:
    target = state_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    previous = load_backend_state() or {}
    state = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "applied": applied,
        "backend": compiled["manifest"]["backend"] if compiled else previous.get("backend"),
        "json_path": compiled["json_path"] if compiled else previous.get("json_path"),
        "nft_path": compiled["nft_path"] if compiled else previous.get("nft_path"),
        "nft_sha256": compiled["nft_sha256"] if compiled else previous.get("nft_sha256"),
    }
    if extra:
        state.update(extra)
    target.write_text(json.dumps(state, indent=2) + "\n")
    return state


def load_backend_state() -> dict | None:
    target = state_path()
    if not target.exists():
        return None
    try:
        return json.loads(target.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def backend_status_report(config: dict | None = None) -> dict:
    state = load_backend_state()
    issues: list[str] = []
    report = {
        "state_path": str(state_path()),
        "configured_backend": config["backend"] if config else None,
        "present": state is not None,
        "applied": bool(state and state.get("applied")),
        "issues": issues,
        "ready": False,
    }

    if not state:
        issues.append("No backend state file has been recorded yet.")
        return report

    report["state"] = state
    json_path = Path(state["json_path"]) if state.get("json_path") else None
    nft_path = Path(state["nft_path"]) if state.get("nft_path") else None

    report["json_exists"] = bool(json_path and json_path.exists())
    report["nft_exists"] = bool(nft_path and nft_path.exists())
    if not state.get("applied"):
        issues.append("Rules are not recorded as applied.")
    if not report["json_exists"]:
        issues.append("Compiled profile JSON is missing.")
    if not report["nft_exists"]:
        issues.append("Compiled nftables rules file is missing.")

    expected_hash = state.get("nft_sha256")
    if expected_hash and nft_path and nft_path.exists():
        actual_hash = sha256(nft_path.read_bytes()).hexdigest()
        report["nft_hash_matches"] = actual_hash == expected_hash
        if actual_hash != expected_hash:
            issues.append("Compiled nftables file no longer matches the recorded backend state.")
    else:
        report["nft_hash_matches"] = None

    if config and config["backend"] == "linux_wsl_nft" and state.get("backend") != "linux_wsl_nft":
        issues.append(
            "The recorded backend state was created for a different backend. Re-run `codex-net apply-rules` "
            "after setting `backend = \"linux_wsl_nft\"`."
        )

    if config and config["backend"] == "linux_wsl_nft":
        prepared = state.get("prepared_slices")
        if not isinstance(prepared, list) or not prepared:
            issues.append(
                "No prepared slice units are recorded in backend state. Re-run `codex-net apply-rules --sudo`."
            )
        else:
            missing_units = []
            for entry in prepared:
                if not isinstance(entry, dict):
                    missing_units.append("<invalid entry>")
                    continue
                slice_name = str(entry.get("slice_name", "")).strip() or "<unknown slice>"
                unit_path = str(entry.get("unit_path", "")).strip()
                if not unit_path or not Path(unit_path).exists():
                    missing_units.append(f"{slice_name} ({unit_path or 'missing unit_path'})")
            if missing_units:
                issues.append(
                    "Recorded slice unit files are missing: "
                    + ", ".join(missing_units)
                    + ". Re-run `codex-net apply-rules --sudo`."
                )

    report["ready"] = not issues
    return report


def _nft_command(use_sudo: bool, *args: str) -> list[str]:
    command = ["nft", *args]
    if use_sudo:
        command.insert(0, "sudo")
    return command


def _looks_like_missing_table(detail: str) -> bool:
    lowered = detail.lower()
    return "no such file or directory" in lowered or "not found" in lowered


def _run_nft(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, check=False, capture_output=True, text=True)
    except FileNotFoundError as exc:
        missing = command[0]
        raise BackendError(f"`{missing}` is required for nftables-backed enforcement.") from exc


def _permission_hint(detail: str, use_sudo: bool) -> str:
    lowered = detail.lower()
    if use_sudo or ("permission denied" not in lowered and "operation not permitted" not in lowered):
        return detail.strip()
    return f"{detail.strip()} Re-run with `--sudo`."


def _run_systemctl(mode: str, args: list[str], use_sudo: bool) -> subprocess.CompletedProcess[str]:
    command = ["systemctl", *(["--user"] if mode == "systemd_user" else []), *args]
    if mode == "systemd_system":
        if not use_sudo:
            raise BackendError("System-scope slice preparation requires `--sudo`.")
        command.insert(0, "sudo")
    try:
        return subprocess.run(command, check=False, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise BackendError("`systemctl` is required for linux_wsl_nft slice preparation.") from exc


def _run_systemd_anchor(mode: str, anchor_unit: str, slice_name: str, use_sudo: bool) -> subprocess.CompletedProcess[str]:
    sleep_binary = shutil.which("sleep") or "/usr/bin/sleep"
    command = [
        "systemd-run",
        *(["--user"] if mode == "systemd_user" else []),
        f"--unit={anchor_unit}",
        f"--slice={slice_name}",
        "--service-type=simple",
        sleep_binary,
        "infinity",
    ]
    if mode == "systemd_system":
        if not use_sudo:
            raise BackendError("System-scope slice preparation requires `--sudo`.")
        command.insert(0, "sudo")
    try:
        return subprocess.run(command, check=False, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise BackendError("`systemd-run` is required for linux_wsl_nft slice preparation.") from exc


def _write_slice_unit_file(path: Path, profile_name: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "[Unit]\n"
        f"Description=Codex network profile slice for {profile_name}\n\n"
        "[Slice]\n"
    )


def _prepare_user_slice(profile_name: str, config: dict) -> dict:
    slice_name = slice_unit_name(profile_name, config, "systemd_user")
    cgroup_path = "/".join(_slice_cgroup_components(slice_name, "systemd_user"))
    anchor_unit = anchor_unit_name(profile_name, config)
    unit_path = DEFAULT_USER_UNIT_DIR / slice_name
    _write_slice_unit_file(unit_path, profile_name)

    reload_result = _run_systemctl("systemd_user", ["daemon-reload"], use_sudo=False)
    if reload_result.returncode != 0:
        raise BackendError(f"Could not reload the user systemd manager: {(reload_result.stderr or reload_result.stdout).strip()}")

    start_result = _run_systemctl("systemd_user", ["start", slice_name], use_sudo=False)
    if start_result.returncode != 0:
        raise BackendError(f"Could not start user slice `{slice_name}`: {(start_result.stderr or start_result.stdout).strip()}")

    anchor_result = _run_systemd_anchor("systemd_user", anchor_unit, slice_name, use_sudo=False)
    if anchor_result.returncode != 0:
        raise BackendError(
            f"Could not start anchor service `{anchor_unit}` in `{slice_name}`: "
            f"{(anchor_result.stderr or anchor_result.stdout).strip()}"
        )

    return {
        "mode": "systemd_user",
        "slice_name": slice_name,
        "unit_path": str(unit_path),
        "anchor_unit": anchor_unit,
        "cgroup_path": cgroup_path,
    }


def _prepare_system_slice(profile_name: str, config: dict, use_sudo: bool) -> dict:
    slice_name = slice_unit_name(profile_name, config, "systemd_system")
    cgroup_path = "/".join(_slice_cgroup_components(slice_name, "systemd_system"))
    anchor_unit = anchor_unit_name(profile_name, config)
    if not use_sudo:
        raise BackendError("System-scope slice preparation requires `--sudo`.")

    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        handle.write(
            "[Unit]\n"
            f"Description=Codex network profile slice for {profile_name}\n\n"
            "[Slice]\n"
        )
        temp_path = handle.name

    try:
        install_result = subprocess.run(
            ["sudo", "install", "-D", "-m", "0644", temp_path, str(SYSTEM_UNIT_DIR / slice_name)],
            check=False,
            capture_output=True,
            text=True,
        )
        if install_result.returncode != 0:
            raise BackendError(f"Could not install system slice unit `{slice_name}`: {(install_result.stderr or install_result.stdout).strip()}")

        reload_result = _run_systemctl("systemd_system", ["daemon-reload"], use_sudo=use_sudo)
        if reload_result.returncode != 0:
            raise BackendError(f"Could not reload the system systemd manager: {(reload_result.stderr or reload_result.stdout).strip()}")

        start_result = _run_systemctl("systemd_system", ["start", slice_name], use_sudo=use_sudo)
        if start_result.returncode != 0:
            raise BackendError(f"Could not start system slice `{slice_name}`: {(start_result.stderr or start_result.stdout).strip()}")

        anchor_result = _run_systemd_anchor("systemd_system", anchor_unit, slice_name, use_sudo=use_sudo)
        if anchor_result.returncode != 0:
            raise BackendError(
                f"Could not start anchor service `{anchor_unit}` in `{slice_name}`: "
                f"{(anchor_result.stderr or anchor_result.stdout).strip()}"
            )
    finally:
        try:
            Path(temp_path).unlink()
        except OSError:
            pass

    return {
        "mode": "systemd_system",
        "slice_name": slice_name,
        "unit_path": str(SYSTEM_UNIT_DIR / slice_name),
        "anchor_unit": anchor_unit,
        "cgroup_path": cgroup_path,
    }


def _remove_slice_entries(prepared: list[dict], use_sudo: bool) -> list[dict]:
    removed: list[dict] = []
    reloaded_modes: set[str] = set()

    for entry in prepared:
        if not isinstance(entry, dict):
            continue
        mode = str(entry.get("mode", "")).strip()
        slice_name = str(entry.get("slice_name", "")).strip()
        unit_path = str(entry.get("unit_path", "")).strip()
        anchor_unit = str(entry.get("anchor_unit", "")).strip()
        if not mode or not slice_name or not unit_path:
            continue

        if anchor_unit:
            stop_anchor_result = _run_systemctl(mode, ["stop", anchor_unit], use_sudo=use_sudo)
            if stop_anchor_result.returncode != 0:
                detail = (stop_anchor_result.stderr or stop_anchor_result.stdout).strip().lower()
                if "not loaded" not in detail and "could not be found" not in detail:
                    raise BackendError(
                        f"Could not stop anchor service `{anchor_unit}`: "
                        f"{(stop_anchor_result.stderr or stop_anchor_result.stdout).strip()}"
                    )

        stop_result = _run_systemctl(mode, ["stop", slice_name], use_sudo=use_sudo)
        if stop_result.returncode != 0:
            detail = (stop_result.stderr or stop_result.stdout).strip().lower()
            if "not loaded" not in detail and "could not be found" not in detail:
                raise BackendError(f"Could not stop slice `{slice_name}`: {(stop_result.stderr or stop_result.stdout).strip()}")

        if mode == "systemd_user":
            try:
                Path(unit_path).unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise BackendError(f"Could not remove user slice unit `{unit_path}`: {exc}") from exc
        else:
            remove_result = subprocess.run(
                ["sudo", "rm", "-f", unit_path],
                check=False,
                capture_output=True,
                text=True,
            )
            if remove_result.returncode != 0:
                raise BackendError(f"Could not remove system slice unit `{unit_path}`: {(remove_result.stderr or remove_result.stdout).strip()}")

        removed.append(
            {
                "mode": mode,
                "slice_name": slice_name,
                "unit_path": unit_path,
                "anchor_unit": anchor_unit,
            }
        )
        reloaded_modes.add(mode)

    for mode in sorted(reloaded_modes):
        reload_result = _run_systemctl(mode, ["daemon-reload"], use_sudo=use_sudo)
        if reload_result.returncode != 0:
            raise BackendError(f"Could not reload the {'user' if mode == 'systemd_user' else 'system'} systemd manager: {(reload_result.stderr or reload_result.stdout).strip()}")

    return removed


def prepare_slice_units(compiled: dict, use_sudo: bool) -> list[dict]:
    manifest = compiled["manifest"]
    config = {"backend_linux_wsl_nft": manifest.get("backend_linux_wsl_nft", {})}
    prepared: list[dict] = []
    mode = _slice_mode(config)

    try:
        for profile_name in sorted(manifest["profiles"]):
            if mode == "systemd_user":
                prepared.append(_prepare_user_slice(profile_name, config))
            else:
                prepared.append(_prepare_system_slice(profile_name, config, use_sudo))
    except BackendError as exc:
        if prepared:
            try:
                _remove_slice_entries(prepared, use_sudo)
            except BackendError as cleanup_exc:
                raise BackendError(
                    f"{exc} Cleanup also failed while removing prepared slice units: {cleanup_exc}"
                ) from cleanup_exc
        raise

    return prepared


def remove_slice_units(use_sudo: bool) -> list[dict]:
    state = load_backend_state() or {}
    prepared = state.get("prepared_slices", [])
    if not isinstance(prepared, list):
        return []
    return _remove_slice_entries(prepared, use_sudo)


def apply_nft_rules(compiled: dict, use_sudo: bool) -> dict:
    nft_socket_report = nft_socket_support_report()
    if not nft_socket_report["ok"]:
        raise BackendError(
            "`linux_wsl_nft` requires kernel support for the nft socket expression (`CONFIG_NFT_SOCKET`). "
            + str(nft_socket_report["detail"])
        )

    nft_path = compiled["nft_path"]
    table = compiled["manifest"]["backend_linux_wsl_nft"].get("nft_table_name", "codex_hardening")
    prepared_slices = prepare_slice_units(compiled, use_sudo)
    try:
        check_command = _nft_command(use_sudo, "-c", "-f", nft_path)
        check_result = _run_nft(check_command)
        if check_result.returncode != 0:
            raise BackendError(
                "nftables syntax validation failed: "
                + _permission_hint(check_result.stderr or check_result.stdout or "unknown error", use_sudo)
            )

        list_command = _nft_command(use_sudo, "list", "table", "inet", table)
        list_result = _run_nft(list_command)
        removed_existing_table = False
        delete_command = None
        if list_result.returncode == 0:
            delete_command = _nft_command(use_sudo, "delete", "table", "inet", table)
            delete_result = _run_nft(delete_command)
            if delete_result.returncode != 0:
                raise BackendError(
                    "Could not remove the previously installed nftables table: "
                    + _permission_hint(delete_result.stderr or delete_result.stdout or "unknown error", use_sudo)
                )
            removed_existing_table = True
        elif not _looks_like_missing_table(list_result.stderr or list_result.stdout or ""):
            raise BackendError(
                "Could not inspect the existing nftables table: "
                + _permission_hint(list_result.stderr or list_result.stdout or "unknown error", use_sudo)
            )

        apply_command = _nft_command(use_sudo, "-f", nft_path)
        apply_result = _run_nft(apply_command)
        if apply_result.returncode != 0:
            raise BackendError(
                "Applying nftables rules failed: "
                + _permission_hint(apply_result.stderr or apply_result.stdout or "unknown error", use_sudo)
            )

        return {
            "table_name": table,
            "prepared_slices": prepared_slices,
            "check_command": check_command,
            "list_command": list_command,
            "delete_command": delete_command,
            "apply_command": apply_command,
            "removed_existing_table": removed_existing_table,
        }
    except BackendError as exc:
        try:
            _remove_slice_entries(prepared_slices, use_sudo)
        except BackendError as cleanup_exc:
            raise BackendError(
                f"{exc} Cleanup also failed while removing prepared slice units: {cleanup_exc}"
            ) from cleanup_exc
        raise


def remove_nft_rules(config: dict, use_sudo: bool) -> dict:
    table = table_name(config)
    removed_slices = remove_slice_units(use_sudo)
    list_command = _nft_command(use_sudo, "list", "table", "inet", table)
    list_result = _run_nft(list_command)
    if list_result.returncode != 0:
        detail = list_result.stderr or list_result.stdout or "unknown error"
        if _looks_like_missing_table(detail):
            return {
                "table_name": table,
                "removed_slices": removed_slices,
                "list_command": list_command,
                "delete_command": None,
                "removed": False,
            }
        raise BackendError(
            "Could not inspect the existing nftables table: " + _permission_hint(detail, use_sudo)
        )

    delete_command = _nft_command(use_sudo, "delete", "table", "inet", table)
    delete_result = _run_nft(delete_command)
    if delete_result.returncode != 0:
        raise BackendError(
            "Removing nftables rules failed: "
            + _permission_hint(delete_result.stderr or delete_result.stdout or "unknown error", use_sudo)
        )

    return {
        "table_name": table,
        "removed_slices": removed_slices,
        "list_command": list_command,
        "delete_command": delete_command,
        "removed": True,
    }
