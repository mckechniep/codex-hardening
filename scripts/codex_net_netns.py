#!/usr/bin/env python3

import os
import shutil
import subprocess
import uuid

from codex_net_wsl import BackendError, _kernel_config_value, detect_environment


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
