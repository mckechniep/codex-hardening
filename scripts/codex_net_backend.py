#!/usr/bin/env python3

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

from codex_net_policy import PolicyError, load_network_profiles, validate_command_for_profile
from codex_net_netns import (
    apply_netns_base,
    netns_backend_status_report,
    netns_doctor_report,
    remove_netns_base,
    run_netns_exec,
    run_netns_spike,
)
from codex_net_wsl import (
    BackendError,
    apply_nft_rules,
    backend_status_report,
    compile_profiles,
    doctor_report,
    remove_nft_rules,
    scope_launch_command,
    scope_runtime_report,
    state_path,
    write_backend_state,
)


def parser() -> argparse.ArgumentParser:
    program = argparse.ArgumentParser(prog="codex-net")
    subcommands = program.add_subparsers(dest="command", required=True)

    exec_parser = subcommands.add_parser("exec", help="Run a command under a named Codex network profile.")
    exec_parser.add_argument("--profile", help="Profile to use. Defaults to the config default profile.")
    exec_parser.add_argument("wrapped_command", nargs=argparse.REMAINDER, help="Command to run after `--`.")

    subcommands.add_parser("list-profiles", help="List the available network profiles.")
    subcommands.add_parser("show-config", help="Show the loaded network profile config path and backend.")
    doctor_parser = subcommands.add_parser("doctor", help="Check WSL nftables backend readiness.")
    doctor_parser.add_argument("--json", action="store_true", help="Print the doctor report as JSON.")
    compile_parser = subcommands.add_parser(
        "compile-profiles",
        help="Resolve profile domains and render nftables-friendly set files.",
    )
    compile_parser.add_argument("--output-dir", help="Directory for compiled profile artifacts.")
    compile_parser.add_argument("--print-nft", action="store_true", help="Print the rendered nftables sets to stdout.")
    apply_parser = subcommands.add_parser(
        "apply-rules",
        help="Compile profiles and apply the generated nftables rules with nft.",
    )
    apply_parser.add_argument("--output-dir", help="Directory for compiled profile artifacts.")
    apply_parser.add_argument("--sudo", action="store_true", help="Run nft via sudo.")
    apply_parser.add_argument("--print-only", action="store_true", help="Compile and print the nft path without applying.")
    remove_parser = subcommands.add_parser(
        "remove-rules",
        help="Remove the installed nftables table for the configured WSL backend.",
    )
    remove_parser.add_argument("--sudo", action="store_true", help="Run nft via sudo.")
    status_parser = subcommands.add_parser("backend-status", help="Show the last recorded backend apply state.")
    status_parser.add_argument("--json", action="store_true", help="Print backend status as JSON.")
    spike_parser = subcommands.add_parser(
        "netns-spike",
        help="Run the experimental namespace feasibility spike for the planned stock-WSL backend.",
    )
    spike_parser.add_argument("--sudo", action="store_true", help="Run namespace setup commands via sudo.")
    spike_parser.add_argument("wrapped_command", nargs=argparse.REMAINDER, help="Command to run after `--`.")
    return program


def load_config() -> dict:
    config = load_network_profiles()
    if not config:
        raise PolicyError(
            "No network profile config was found. Install or create ~/.codex/policies/network_profiles.toml first."
        )
    return config


def cmd_exec(args: argparse.Namespace) -> int:
    config = load_config()
    profile = args.profile or config["default_profile"]
    wrapped_command = list(args.wrapped_command)
    if wrapped_command and wrapped_command[0] == "--":
        wrapped_command = wrapped_command[1:]
    if not wrapped_command:
        raise PolicyError("`codex-net exec` requires a wrapped command after `--`.")

    command_text = shlex.join(wrapped_command)
    validate_command_for_profile(command_text, profile, config)

    backend = config["backend"]
    if backend not in {"hook_only", "linux_wsl_nft", "linux_wsl_netns"}:
        raise PolicyError(f"Unsupported network backend `{backend}`.")

    if backend == "linux_wsl_nft":
        report = backend_status_report(config)
        if not report["ready"]:
            raise PolicyError(
                "The linux_wsl_nft backend is not ready: "
                + " ".join(report["issues"])
                + " Run `codex-net apply-rules --sudo` again."
            )
        runtime = scope_runtime_report(config)
        if not runtime["ok"]:
            raise PolicyError(str(runtime["detail"]))
        command = scope_launch_command(profile, wrapped_command, config, mode=str(runtime["selected_mode"]))
        try:
            return subprocess.run(command).returncode
        except FileNotFoundError as exc:
            raise PolicyError("systemd-run is required for the linux_wsl_nft backend.") from exc

    if backend == "linux_wsl_netns":
        return run_netns_exec(profile, wrapped_command, config)

    os.execvp(wrapped_command[0], wrapped_command)
    return 0


def cmd_list_profiles() -> int:
    config = load_config()
    default_profile = config["default_profile"]
    for name, profile in sorted(config["profiles"].items()):
        suffix = " (default)" if name == default_profile else ""
        description = profile["description"] or "No description."
        print(f"{name}{suffix}: {description}")
    return 0


def cmd_show_config() -> int:
    config = load_config()
    print(f"path: {config['path']}")
    print(f"backend: {config['backend']}")
    print(f"default_profile: {config['default_profile']}")
    return 0


def cmd_doctor(as_json: bool) -> int:
    report = doctor_report()
    netns_report = netns_doctor_report()
    if as_json:
        payload = {
            **report,
            "backend_readiness": {
                "linux_wsl_nft": report["ready"],
                "linux_wsl_netns": netns_report["ready"],
            },
            "netns_checks": netns_report["checks"],
        }
        print(json.dumps(payload, indent=2))
        return 0

    env = report["environment"]
    print(f"platform: {env['platform']}")
    print(f"osrelease: {env['osrelease'] or 'unknown'}")
    print(f"is_wsl2: {env['is_wsl2']}")
    print(f"ready: {'yes' if report['ready'] else 'no'}")
    print(f"linux_wsl_nft_ready: {'yes' if report['ready'] else 'no'}")
    print(f"linux_wsl_netns_ready: {'yes' if netns_report['ready'] else 'no'}")
    for check in report["checks"]:
        status = "ok" if check["ok"] == "true" else "missing"
        suffix = "required" if check["required"] == "true" else "recommended"
        print(f"{check['name']}: {status} ({suffix})")
        print(f"  {check['detail']}")
    print("netns_checks:")
    for check in netns_report["checks"]:
        status = "ok" if check["ok"] == "true" else "missing"
        suffix = "required" if check["required"] == "true" else "recommended"
        print(f"  {check['name']}: {status} ({suffix})")
        print(f"    {check['detail']}")
    return 0


def cmd_compile_profiles(output_dir: str | None, print_nft: bool) -> int:
    config = load_config()
    compiled = compile_profiles(config, Path(output_dir) if output_dir else None)
    print(f"output_dir: {compiled['output_dir']}")
    print(f"json_path: {compiled['json_path']}")
    print(f"nft_path: {compiled['nft_path']}")
    print(f"nft_sha256: {compiled['nft_sha256']}")
    print(f"profile_count: {compiled['profile_count']}")
    print(f"resolved_domains: {compiled['resolved_domain_count']}")
    print(f"unresolved_domains: {compiled['unresolved_domain_count']}")
    if print_nft:
        print("---")
        print(Path(compiled["nft_path"]).read_text(), end="")
    return 0


def cmd_apply_rules(output_dir: str | None, use_sudo: bool, print_only: bool) -> int:
    config = load_config()
    if config["backend"] == "linux_wsl_netns":
        details = apply_netns_base(config, use_sudo=use_sudo)
        write_backend_state(
            {
                "json_path": None,
                "nft_path": None,
                "nft_sha256": None,
                "manifest": {"backend": "linux_wsl_netns"},
            },
            applied=True,
            extra=details,
        )
        print(f"backend_state: {state_path()}")
        print(f"table_name: {details['table_name']}")
        print(f"base_nft_path: {details['base_nft_path']}")
        print(f"base_nft_sha256: {details['base_nft_sha256']}")
        print(f"removed_existing_table: {details['removed_existing_table']}")
        return 0

    compiled = compile_profiles(config, Path(output_dir) if output_dir else None)
    print(f"nft_path: {compiled['nft_path']}")
    print(f"nft_sha256: {compiled['nft_sha256']}")

    if print_only:
        return 0

    details = apply_nft_rules(compiled, use_sudo)
    write_backend_state(compiled, applied=True, extra=details)
    print(f"backend_state: {state_path()}")
    print(f"table_name: {details['table_name']}")
    print(f"removed_existing_table: {details['removed_existing_table']}")
    return 0


def cmd_remove_rules(use_sudo: bool) -> int:
    config = load_config()
    if config["backend"] == "linux_wsl_netns":
        details = remove_netns_base(config, use_sudo=use_sudo)
        write_backend_state(None, applied=False, extra=details)
        print(f"backend_state: {state_path()}")
        print(f"table_name: {details['table_name']}")
        print(f"removed: {details['removed']}")
        return 0

    details = remove_nft_rules(config, use_sudo)
    write_backend_state(None, applied=False, extra=details)
    print(f"backend_state: {state_path()}")
    print(f"table_name: {details['table_name']}")
    print(f"removed: {details['removed']}")
    return 0


def cmd_backend_status(as_json: bool) -> int:
    config = load_network_profiles()
    if config and config["backend"] == "linux_wsl_netns":
        report = netns_backend_status_report(config)
    else:
        report = backend_status_report(config)
    if as_json:
        print(json.dumps(report, indent=2))
        return 0

    print(f"state_path: {report['state_path']}")
    print(f"configured_backend: {report.get('configured_backend')}")
    print(f"ready: {'yes' if report['ready'] else 'no'}")
    if report.get("state"):
        state = report["state"]
        for key in ("updated_at", "applied", "backend", "json_path", "nft_path", "nft_sha256"):
            print(f"{key}: {state.get(key)}")
        for key in ("base_nft_path", "base_nft_sha256"):
            if key in state:
                print(f"{key}: {state.get(key)}")
    if "active_exec_count" in report:
        print(f"active_exec_count: {report['active_exec_count']}")
    for issue in report["issues"]:
        print(f"issue: {issue}")
    return 0


def cmd_netns_spike(args: argparse.Namespace) -> int:
    wrapped_command = list(args.wrapped_command)
    if wrapped_command and wrapped_command[0] == "--":
        wrapped_command = wrapped_command[1:]
    details = run_netns_spike(wrapped_command, use_sudo=args.sudo)
    print("backend: linux_wsl_netns")
    print("mode: feasibility_spike")
    print(f"namespace: {details['namespace']}")
    print(f"host_veth: {details['host_veth']}")
    print(f"guest_veth: {details['guest_veth']}")
    print(f"subnet: {details['subnet']}")
    print(f"host_ip: {details['host_ip']}")
    print(f"guest_ip: {details['guest_ip']}")
    print(f"returncode: {details['returncode']}")
    return int(details["returncode"])


def main() -> int:
    args = parser().parse_args()
    if args.command == "exec":
        return cmd_exec(args)
    if args.command == "list-profiles":
        return cmd_list_profiles()
    if args.command == "show-config":
        return cmd_show_config()
    if args.command == "doctor":
        return cmd_doctor(args.json)
    if args.command == "compile-profiles":
        return cmd_compile_profiles(args.output_dir, args.print_nft)
    if args.command == "apply-rules":
        return cmd_apply_rules(args.output_dir, args.sudo, args.print_only)
    if args.command == "remove-rules":
        return cmd_remove_rules(args.sudo)
    if args.command == "netns-spike":
        return cmd_netns_spike(args)
    return cmd_backend_status(args.json)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BackendError, PolicyError) as exc:
        sys.stderr.write(f"codex-net: {exc}\n")
        raise SystemExit(2)
