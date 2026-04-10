#!/usr/bin/env python3

import fcntl
import json
import os
import shutil
import subprocess
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from codex_net_wsl import BackendError, _kernel_config_value, detect_environment, load_backend_state, state_path


def _tool_check(name: str, executable: str, required: bool, detail: str) -> dict[str, str]:
    return {
        "name": name,
        "required": "true" if required else "false",
        "ok": "true" if shutil.which(executable) else "false",
        "detail": detail,
    }


def _kernel_check(name: str, symbol: str, required: bool, detail: str) -> dict[str, str]:
    value = _kernel_config_value(symbol)
    return {
        "name": name,
        "required": "true" if required else "false",
        "ok": "true" if value in {"y", "m"} else "false",
        "detail": f"{detail} {symbol}={value or 'unknown'}",
    }


def netns_doctor_report() -> dict:
    env = detect_environment()
    checks = [
        {
            "name": "linux",
            "required": "true",
            "ok": env["is_linux"],
            "detail": "Linux is required for a namespace-backed WSL backend.",
        },
        {
            "name": "wsl2",
            "required": "true",
            "ok": env["is_wsl2"],
            "detail": "WSL 2 is the supported target for the namespace feasibility spike.",
        },
        _tool_check("sudo", "sudo", True, "`sudo` is required to create and destroy network namespaces."),
        _tool_check("ip", "ip", True, "The `ip` command is required for namespace and veth management."),
        _tool_check("nft", "nft", True, "The `nft` command is required for the planned host-side namespace firewalling."),
        _tool_check("unshare", "unshare", False, "`unshare` is useful for namespace diagnostics during development."),
        _tool_check("nsenter", "nsenter", False, "`nsenter` is useful for namespace diagnostics during development."),
        _tool_check("setpriv", "setpriv", True, "`setpriv` is used to drop from root back to the calling user inside the namespace."),
        _kernel_check("net_ns", "CONFIG_NET_NS", True, "Network namespaces must be enabled in the kernel."),
        _kernel_check("veth", "CONFIG_VETH", True, "Virtual ethernet pairs must be enabled in the kernel."),
        _kernel_check("nf_nat", "CONFIG_NF_NAT", True, "NAT support is needed for the planned namespace backend."),
    ]
    ready = all(item["ok"] == "true" for item in checks if item["required"] == "true")
    return {
        "environment": env,
        "checks": checks,
        "ready": ready,
    }


def netns_runtime_root() -> Path:
    return state_path().parent / "netns"


def netns_exec_dir() -> Path:
    return netns_runtime_root() / "executions"


def netns_lock_file() -> Path:
    return netns_runtime_root() / "runtime.lock"


def netns_base_rules_path() -> Path:
    return netns_runtime_root() / "base_runtime.nft"


def netns_table_name(config: dict) -> str:
    backend = config.get("backend_linux_wsl_netns", {})
    name = str(backend.get("nft_table_name", "codex_netns_runtime")).strip()
    return name or "codex_netns_runtime"


def _ensure_runtime_layout() -> None:
    netns_exec_dir().mkdir(parents=True, exist_ok=True)
    netns_lock_file().touch(exist_ok=True)


@contextmanager
def runtime_lock():
    _ensure_runtime_layout()
    with netns_lock_file().open("r+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _execution_record_path(token: str) -> Path:
    return netns_exec_dir() / f"{token}.json"


def _write_execution_record(token: str, payload: dict) -> Path:
    with runtime_lock():
        path = _execution_record_path(token)
        path.write_text(json.dumps(payload, indent=2) + "\n")
    return path


def _remove_execution_record(token: str) -> None:
    with runtime_lock():
        path = _execution_record_path(token)
        try:
            path.unlink()
        except FileNotFoundError:
            return


def list_execution_records() -> list[dict]:
    _ensure_runtime_layout()
    records: list[dict] = []
    for path in sorted(netns_exec_dir().glob("*.json")):
        try:
            payload = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            payload = {"id": path.stem, "record_path": str(path), "status": "corrupt"}
        else:
            payload["record_path"] = str(path)
        records.append(payload)
    return records


def _sudo_command(command: list[str], use_sudo: bool) -> list[str]:
    if use_sudo:
        return ["sudo", *command]
    return command


def _run_checked(command: list[str], step: str, *, use_sudo: bool, cwd: str | None = None) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            _sudo_command(command, use_sudo),
            check=False,
            capture_output=True,
            text=True,
            cwd=cwd,
        )
    except FileNotFoundError as exc:
        raise BackendError(f"{step} failed because `{command[0]}` is not installed.") from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or f"exit code {result.returncode}"
        raise BackendError(f"{step} failed: {detail}")
    return result


def _run_best_effort(command: list[str], *, use_sudo: bool) -> None:
    try:
        subprocess.run(
            _sudo_command(command, use_sudo),
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return


def render_base_rules(config: dict) -> str:
    table_name = netns_table_name(config)
    return (
        "# Generated by codex-net apply-rules for linux_wsl_netns\n"
        "# This is base runtime scaffolding only. Per-execution rules are added later.\n\n"
        f"table inet {table_name} {{\n"
        "    chain codex_netns_forward {\n"
        "        type filter hook forward priority filter; policy accept;\n"
        "    }\n\n"
        "    chain codex_netns_output {\n"
        "        type filter hook output priority filter; policy accept;\n"
        "    }\n\n"
        "    chain codex_netns_postrouting {\n"
        "        type nat hook postrouting priority srcnat; policy accept;\n"
        "    }\n"
        "}\n"
    )


def _run_nft(command: list[str], *, use_sudo: bool) -> subprocess.CompletedProcess[str]:
    return _run_checked(command, "nft invocation", use_sudo=use_sudo)


def apply_netns_base(config: dict, *, use_sudo: bool) -> dict:
    report = netns_doctor_report()
    if not report["ready"]:
        missing = [item["name"] for item in report["checks"] if item["required"] == "true" and item["ok"] != "true"]
        raise BackendError(
            "The linux_wsl_netns backend is not ready on this host. Missing prerequisites: "
            + ", ".join(missing)
            + "."
        )
    _ensure_runtime_layout()
    rules = render_base_rules(config)
    base_path = netns_base_rules_path()
    base_path.write_text(rules)
    base_hash = sha256(base_path.read_bytes()).hexdigest()
    table = netns_table_name(config)

    check_command = ["nft", "-c", "-f", str(base_path)]
    _run_nft(check_command, use_sudo=use_sudo)

    list_command = ["nft", "list", "table", "inet", table]
    list_result = subprocess.run(
        _sudo_command(list_command, use_sudo),
        check=False,
        capture_output=True,
        text=True,
    )
    removed_existing_table = False
    if list_result.returncode == 0:
        delete_command = ["nft", "delete", "table", "inet", table]
        _run_nft(delete_command, use_sudo=use_sudo)
        removed_existing_table = True
    else:
        delete_command = None

    apply_command = ["nft", "-f", str(base_path)]
    _run_nft(apply_command, use_sudo=use_sudo)
    return {
        "table_name": table,
        "base_nft_path": str(base_path),
        "base_nft_sha256": base_hash,
        "runtime_root": str(netns_runtime_root()),
        "runtime_exec_dir": str(netns_exec_dir()),
        "lock_path": str(netns_lock_file()),
        "removed_existing_table": removed_existing_table,
        "check_command": check_command,
        "list_command": list_command,
        "delete_command": delete_command,
        "apply_command": apply_command,
    }


def remove_netns_base(config: dict, *, use_sudo: bool) -> dict:
    table = netns_table_name(config)
    active_records = list_execution_records()
    if active_records:
        raise BackendError(
            "Refusing to remove the linux_wsl_netns base runtime while execution records still exist: "
            + ", ".join(str(record.get("id", "<unknown>")) for record in active_records)
        )

    list_command = ["nft", "list", "table", "inet", table]
    list_result = subprocess.run(
        _sudo_command(list_command, use_sudo),
        check=False,
        capture_output=True,
        text=True,
    )
    if list_result.returncode != 0:
        return {
            "table_name": table,
            "removed": False,
            "list_command": list_command,
            "delete_command": None,
        }

    delete_command = ["nft", "delete", "table", "inet", table]
    _run_nft(delete_command, use_sudo=use_sudo)
    return {
        "table_name": table,
        "removed": True,
        "list_command": list_command,
        "delete_command": delete_command,
    }


def netns_backend_status_report(config: dict | None) -> dict:
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
    records = list_execution_records()
    report["active_exec_count"] = len(records)
    report["active_exec_records"] = records
    report["runtime_root"] = str(netns_runtime_root())
    report["lock_path"] = str(netns_lock_file())

    if not state:
        issues.append("No backend state file has been recorded yet.")
        return report

    report["state"] = state
    if state.get("backend") != "linux_wsl_netns":
        issues.append("The recorded backend state was created for a different backend.")
    if not state.get("applied"):
        issues.append("Rules are not recorded as applied.")

    base_path = Path(str(state.get("base_nft_path", ""))) if state.get("base_nft_path") else None
    report["base_nft_exists"] = bool(base_path and base_path.exists())
    if not report["base_nft_exists"]:
        issues.append("The netns base nftables file is missing.")
    else:
        expected_hash = str(state.get("base_nft_sha256", "")).strip()
        if expected_hash:
            actual_hash = sha256(base_path.read_bytes()).hexdigest()
            report["base_nft_hash_matches"] = actual_hash == expected_hash
            if actual_hash != expected_hash:
                issues.append("The netns base nftables file no longer matches the recorded backend state.")
        else:
            report["base_nft_hash_matches"] = None

    report["ready"] = not issues
    return report


def _namespace_token() -> str:
    return uuid.uuid4().hex[:8]


def namespace_name(token: str) -> str:
    return f"codex-net-{token}"


def host_veth_name(token: str) -> str:
    return f"cnh{token}"[:15]


def guest_veth_name(token: str) -> str:
    return f"cng{token}"[:15]


def address_plan(token: str) -> dict[str, str]:
    octet3 = 1 + (int(token[:2], 16) % 250)
    octet4_base = (int(token[2:4], 16) % 63) * 4
    subnet = f"169.254.{octet3}.{octet4_base}/30"
    host_ip = f"169.254.{octet3}.{octet4_base + 1}"
    guest_ip = f"169.254.{octet3}.{octet4_base + 2}"
    return {
        "subnet": subnet,
        "host_ip": host_ip,
        "guest_ip": guest_ip,
        "host_cidr": f"{host_ip}/30",
        "guest_cidr": f"{guest_ip}/30",
    }


def namespace_launch_command(namespace: str, uid: int, gid: int, wrapped_command: list[str]) -> list[str]:
    if not wrapped_command:
        raise BackendError("The namespace spike requires a wrapped command after `--`.")
    return [
        "ip",
        "netns",
        "exec",
        namespace,
        "setpriv",
        "--reuid",
        str(uid),
        "--regid",
        str(gid),
        "--init-groups",
        "--",
        *wrapped_command,
    ]


def run_netns_spike(wrapped_command: list[str], *, use_sudo: bool) -> dict:
    if not wrapped_command:
        raise BackendError("The namespace spike requires a wrapped command after `--`.")
    if not use_sudo and os.geteuid() != 0:
        raise BackendError("The namespace spike needs `--sudo` unless it is already running as root.")

    report = netns_doctor_report()
    if not report["ready"]:
        missing = [item["name"] for item in report["checks"] if item["required"] == "true" and item["ok"] != "true"]
        raise BackendError(
            "The namespace feasibility spike is not ready on this host. Missing prerequisites: "
            + ", ".join(missing)
            + "."
        )

    token = _namespace_token()
    namespace = namespace_name(token)
    host_veth = host_veth_name(token)
    guest_veth = guest_veth_name(token)
    addresses = address_plan(token)
    cwd = os.getcwd()
    uid = os.getuid()
    gid = os.getgid()
    record = {
        "id": token,
        "backend": "linux_wsl_netns",
        "mode": "feasibility_spike",
        "status": "preparing",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "namespace": namespace,
        "host_veth": host_veth,
        "guest_veth": guest_veth,
        "subnet": addresses["subnet"],
        "host_ip": addresses["host_ip"],
        "guest_ip": addresses["guest_ip"],
        "command": wrapped_command,
    }
    _write_execution_record(token, record)

    namespace_created = False
    host_veth_created = False
    try:
        _run_checked(["ip", "netns", "add", namespace], "Namespace creation", use_sudo=use_sudo)
        namespace_created = True
        _run_checked(
            ["ip", "link", "add", host_veth, "type", "veth", "peer", "name", guest_veth],
            "veth pair creation",
            use_sudo=use_sudo,
        )
        host_veth_created = True
        _run_checked(["ip", "link", "set", guest_veth, "netns", namespace], "Guest veth move", use_sudo=use_sudo)
        _run_checked(["ip", "addr", "add", addresses["host_cidr"], "dev", host_veth], "Host veth address assignment", use_sudo=use_sudo)
        _run_checked(["ip", "link", "set", host_veth, "up"], "Host veth activation", use_sudo=use_sudo)
        _run_checked(["ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up"], "Namespace loopback activation", use_sudo=use_sudo)
        _run_checked(
            ["ip", "netns", "exec", namespace, "ip", "addr", "add", addresses["guest_cidr"], "dev", guest_veth],
            "Guest veth address assignment",
            use_sudo=use_sudo,
        )
        _run_checked(
            ["ip", "netns", "exec", namespace, "ip", "link", "set", guest_veth, "up"],
            "Guest veth activation",
            use_sudo=use_sudo,
        )
        _run_checked(
            ["ip", "netns", "exec", namespace, "ip", "route", "add", "default", "via", addresses["host_ip"], "dev", guest_veth],
            "Default route installation",
            use_sudo=use_sudo,
        )

        launch = namespace_launch_command(namespace, uid, gid, wrapped_command)
        record["status"] = "running"
        _write_execution_record(token, record)
        result = subprocess.run(
            _sudo_command(launch, use_sudo),
            check=False,
            cwd=cwd,
            env=dict(os.environ),
        )
        return {
            "namespace": namespace,
            "host_veth": host_veth,
            "guest_veth": guest_veth,
            "subnet": addresses["subnet"],
            "host_ip": addresses["host_ip"],
            "guest_ip": addresses["guest_ip"],
            "returncode": result.returncode,
            "launch_command": launch,
        }
    finally:
        if host_veth_created:
            _run_best_effort(["ip", "link", "del", host_veth], use_sudo=use_sudo)
        if namespace_created:
            _run_best_effort(["ip", "netns", "del", namespace], use_sudo=use_sudo)
        _remove_execution_record(token)
