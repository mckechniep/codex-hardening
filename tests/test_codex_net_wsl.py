import os
import subprocess
import sys
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import codex_net_wsl
from codex_net_wsl import (
    BackendError,
    apply_nft_rules,
    backend_status_report,
    nft_socket_support_report,
    prepare_slice_units,
    render_nftables_rules,
    scope_launch_command,
    scope_runtime_report,
    write_backend_state,
)


def sample_config(
    *,
    backend: str = "linux_wsl_nft",
    use_systemd_user: bool = True,
) -> dict:
    return {
        "backend": backend,
        "backend_linux_wsl_nft": {
            "scope_unit_prefix": "codex-net",
            "use_systemd_user": use_systemd_user,
            "nft_table_name": "codex_hardening",
        },
    }


class BackendStatusReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.state_path = Path(self.tempdir.name) / "backend_state.json"
        self.original_state_path = os.environ.get("CODEX_NET_STATE_PATH")
        os.environ["CODEX_NET_STATE_PATH"] = str(self.state_path)
        self.addCleanup(self.restore_env)

    def restore_env(self) -> None:
        if self.original_state_path is None:
            os.environ.pop("CODEX_NET_STATE_PATH", None)
        else:
            os.environ["CODEX_NET_STATE_PATH"] = self.original_state_path

    def test_backend_status_report_handles_missing_state(self) -> None:
        report = backend_status_report(sample_config())
        self.assertFalse(report["present"])
        self.assertFalse(report["ready"])
        self.assertIn("No backend state file has been recorded yet.", report["issues"])

    def test_backend_status_report_accepts_matching_compiled_state(self) -> None:
        compiled_dir = Path(self.tempdir.name) / "compiled"
        compiled_dir.mkdir()
        json_path = compiled_dir / "network_profiles.compiled.json"
        nft_path = compiled_dir / "network_profiles.compiled.nft"
        slice_unit = compiled_dir / "app-codex-net-registries.slice"
        json_path.write_text("{}\n")
        nft_path.write_text("table inet codex_hardening {}\n")
        slice_unit.write_text("[Unit]\nDescription=Test slice\n")

        compiled = {
            "json_path": str(json_path),
            "nft_path": str(nft_path),
            "nft_sha256": sha256(nft_path.read_bytes()).hexdigest(),
            "manifest": {"backend": "linux_wsl_nft"},
        }
        write_backend_state(
            compiled,
            applied=True,
            extra={
                "prepared_slices": [
                    {
                        "mode": "systemd_user",
                        "slice_name": "app-codex-net-registries.slice",
                        "unit_path": str(slice_unit),
                    }
                ]
            },
        )

        report = backend_status_report(sample_config())
        self.assertTrue(report["present"])
        self.assertTrue(report["ready"])
        self.assertEqual(report["issues"], [])

    def test_backend_status_report_flags_backend_mismatch(self) -> None:
        compiled_dir = Path(self.tempdir.name) / "compiled"
        compiled_dir.mkdir()
        json_path = compiled_dir / "network_profiles.compiled.json"
        nft_path = compiled_dir / "network_profiles.compiled.nft"
        json_path.write_text("{}\n")
        nft_path.write_text("table inet codex_hardening {}\n")

        compiled = {
            "json_path": str(json_path),
            "nft_path": str(nft_path),
            "nft_sha256": sha256(nft_path.read_bytes()).hexdigest(),
            "manifest": {"backend": "hook_only"},
        }
        write_backend_state(compiled, applied=True)

        report = backend_status_report(sample_config())
        self.assertFalse(report["ready"])
        self.assertTrue(any("different backend" in issue for issue in report["issues"]))

    def test_backend_status_report_flags_missing_prepared_slice_unit(self) -> None:
        compiled_dir = Path(self.tempdir.name) / "compiled"
        compiled_dir.mkdir()
        json_path = compiled_dir / "network_profiles.compiled.json"
        nft_path = compiled_dir / "network_profiles.compiled.nft"
        json_path.write_text("{}\n")
        nft_path.write_text("table inet codex_hardening {}\n")
        missing_unit = compiled_dir / "missing.slice"

        compiled = {
            "json_path": str(json_path),
            "nft_path": str(nft_path),
            "nft_sha256": sha256(nft_path.read_bytes()).hexdigest(),
            "manifest": {"backend": "linux_wsl_nft"},
        }
        write_backend_state(
            compiled,
            applied=True,
            extra={
                "prepared_slices": [
                    {
                        "mode": "systemd_user",
                        "slice_name": "app-codex-net-registries.slice",
                        "unit_path": str(missing_unit),
                    }
                ]
            },
        )

        report = backend_status_report(sample_config())
        self.assertFalse(report["ready"])
        self.assertTrue(any("Recorded slice unit files are missing" in issue for issue in report["issues"]))


class ScopeLaunchCommandTests(unittest.TestCase):
    def test_scope_launch_command_uses_user_scope_by_default(self) -> None:
        command = scope_launch_command(
            "git_readonly",
            ["git", "clone", "https://github.com/openai/codex.git"],
            sample_config(),
        )
        self.assertEqual(command[:5], ["systemd-run", "--user", "--scope", "--unit=codex-net-git-readonly.scope", "--slice=app-codex-net-git-readonly.slice"])

    def test_scope_launch_command_uses_sudo_for_system_scope(self) -> None:
        command = scope_launch_command(
            "registries",
            ["curl", "https://github.com"],
            sample_config(use_systemd_user=False),
        )
        self.assertEqual(command[:5], ["sudo", "systemd-run", "--scope", "--unit=codex-net-registries.scope", "--slice=system-codex-net-registries.slice"])

    def test_scope_launch_command_respects_explicit_mode_override(self) -> None:
        command = scope_launch_command(
            "registries",
            ["curl", "https://github.com"],
            sample_config(),
            mode="systemd_system",
        )
        self.assertEqual(command[:5], ["sudo", "systemd-run", "--scope", "--unit=codex-net-registries.scope", "--slice=system-codex-net-registries.slice"])


class ScopeRuntimeReportTests(unittest.TestCase):
    @mock.patch.object(codex_net_wsl, "default_scope_runtime_report")
    def test_scope_runtime_report_uses_user_scope_when_available(
        self,
        mock_user_report: mock.Mock,
    ) -> None:
        mock_user_report.return_value = {
            "ok": True,
            "mode": "systemd_user",
            "detail": "user manager ok",
        }

        report = scope_runtime_report(sample_config())
        self.assertTrue(report["ok"])
        self.assertEqual(report["selected_mode"], "systemd_user")
        self.assertFalse(report["fallback_used"])

    @mock.patch.object(codex_net_wsl, "default_scope_runtime_report")
    def test_scope_runtime_report_stays_on_user_scope_when_unavailable(
        self,
        mock_user_report: mock.Mock,
    ) -> None:
        mock_user_report.return_value = {
            "ok": False,
            "mode": "systemd_user",
            "detail": "user bus unavailable",
        }

        report = scope_runtime_report(sample_config())
        self.assertFalse(report["ok"])
        self.assertEqual(report["selected_mode"], "systemd_user")
        self.assertFalse(report["fallback_used"])


class RenderNftablesRulesTests(unittest.TestCase):
    def test_render_nftables_rules_uses_user_slice_names(self) -> None:
        manifest = {
            "source_path": "/tmp/policy.toml",
            "backend_linux_wsl_nft": {
                "use_systemd_user": True,
                "nft_table_name": "codex_hardening",
                "chain_name": "codex_net_output",
            },
            "resolvers": {"ipv4": [], "ipv6": []},
            "profiles": {
                "registries": {
                    "allow_localhost": True,
                    "allowed_tcp_ports": [443],
                    "allowed_udp_ports": [53],
                    "resolved_ipv4": ["140.82.112.3"],
                    "resolved_ipv6": [],
                    "set_names": {
                        "ipv4": "registries_ipv4",
                        "ipv6": "registries_ipv6",
                        "tcp_ports": "registries_tcp_ports",
                        "udp_ports": "registries_udp_ports",
                    },
                    "runtime_units": {
                        "mode": "systemd_user",
                        "scope_unit": "codex-net-registries.scope",
                        "slice_unit": "app-codex-net-registries.slice",
                        "cgroup_match_level": 7,
                        "cgroup_path": "user.slice/user-1000.slice/user@1000.service/app.slice/app-codex.slice/app-codex-net.slice/app-codex-net-registries.slice",
                    },
                }
            },
        }

        rendered = render_nftables_rules(manifest)
        self.assertIn(
            'socket cgroupv2 level 7 "user.slice/user-1000.slice/user@1000.service/app.slice/app-codex.slice/app-codex-net.slice/app-codex-net-registries.slice"',
            rendered,
        )
        self.assertNotIn("codex-net-registries.scope", rendered)

    def test_render_nftables_rules_uses_system_slice_names(self) -> None:
        manifest = {
            "source_path": "/tmp/policy.toml",
            "backend_linux_wsl_nft": {
                "use_systemd_user": False,
                "nft_table_name": "codex_hardening",
                "chain_name": "codex_net_output",
            },
            "resolvers": {"ipv4": [], "ipv6": []},
            "profiles": {
                "registries": {
                    "allow_localhost": True,
                    "allowed_tcp_ports": [443],
                    "allowed_udp_ports": [],
                    "resolved_ipv4": ["140.82.112.3"],
                    "resolved_ipv6": [],
                    "set_names": {
                        "ipv4": "registries_ipv4",
                        "ipv6": "registries_ipv6",
                        "tcp_ports": "registries_tcp_ports",
                        "udp_ports": "registries_udp_ports",
                    },
                    "runtime_units": {
                        "mode": "systemd_system",
                        "scope_unit": "codex-net-registries.scope",
                        "slice_unit": "system-codex-net-registries.slice",
                        "cgroup_match_level": 4,
                        "cgroup_path": "system.slice/system-codex.slice/system-codex-net.slice/system-codex-net-registries.slice",
                    },
                }
            },
        }

        rendered = render_nftables_rules(manifest)
        self.assertIn(
            'socket cgroupv2 level 4 "system.slice/system-codex.slice/system-codex-net.slice/system-codex-net-registries.slice"',
            rendered,
        )

    def test_render_nftables_rules_allows_wildcard_remote_profile_ports(self) -> None:
        manifest = {
            "source_path": "/tmp/policy.toml",
            "backend_linux_wsl_nft": {
                "use_systemd_user": True,
                "nft_table_name": "codex_hardening",
                "chain_name": "codex_net_output",
            },
            "resolvers": {"ipv4": ["172.20.0.1"], "ipv6": []},
            "profiles": {
                "relaxed_network": {
                    "allow_localhost": True,
                    "allow_any_remote": True,
                    "allowed_tcp_ports": [80, 443],
                    "allowed_udp_ports": [53],
                    "resolved_ipv4": [],
                    "resolved_ipv6": [],
                    "set_names": {
                        "ipv4": "relaxed_network_ipv4",
                        "ipv6": "relaxed_network_ipv6",
                        "tcp_ports": "relaxed_network_tcp_ports",
                        "udp_ports": "relaxed_network_udp_ports",
                    },
                    "runtime_units": {
                        "mode": "systemd_user",
                        "scope_unit": "codex-net-relaxed-network.scope",
                        "slice_unit": "app-codex-net-relaxed-network.slice",
                        "cgroup_match_level": 7,
                        "cgroup_path": "user.slice/user-1000.slice/user@1000.service/app.slice/app-codex.slice/app-codex-net.slice/app-codex-net-relaxed-network.slice",
                    },
                }
            },
        }

        rendered = render_nftables_rules(manifest)

        self.assertIn('oifname != "lo" tcp dport @relaxed_network_tcp_ports accept', rendered)
        self.assertIn('oifname != "lo" udp dport @relaxed_network_udp_ports accept', rendered)


class KernelCapabilityTests(unittest.TestCase):
    @mock.patch.object(codex_net_wsl, "_kernel_config_value", return_value="y")
    def test_nft_socket_support_report_accepts_enabled_kernel(self, mock_value: mock.Mock) -> None:
        report = nft_socket_support_report()
        self.assertTrue(report["ok"])
        self.assertEqual(report["config_value"], "y")

    @mock.patch.object(codex_net_wsl, "_kernel_config_value", return_value="n")
    def test_nft_socket_support_report_flags_missing_kernel_support(self, mock_value: mock.Mock) -> None:
        report = nft_socket_support_report()
        self.assertFalse(report["ok"])
        self.assertIn("CONFIG_NFT_SOCKET is not set", str(report["detail"]))


class SliceLifecycleTests(unittest.TestCase):
    @mock.patch.object(codex_net_wsl, "_remove_slice_entries")
    @mock.patch.object(codex_net_wsl, "_prepare_user_slice")
    def test_prepare_slice_units_rolls_back_on_partial_failure(
        self,
        mock_prepare_user_slice: mock.Mock,
        mock_remove_slice_entries: mock.Mock,
    ) -> None:
        compiled = {
            "manifest": {
                "backend_linux_wsl_nft": {
                    "scope_unit_prefix": "codex-net",
                    "use_systemd_user": True,
                },
                "profiles": {
                    "dev_local": {},
                    "registries": {},
                },
            }
        }
        first_slice = {
            "mode": "systemd_user",
            "slice_name": "app-codex-net-dev-local.slice",
            "unit_path": "/tmp/app-codex-net-dev-local.slice",
        }
        mock_prepare_user_slice.side_effect = [
            first_slice,
            BackendError("boom"),
        ]

        with self.assertRaisesRegex(BackendError, "boom"):
            prepare_slice_units(compiled, use_sudo=False)

        mock_remove_slice_entries.assert_called_once_with([first_slice], False)

    @mock.patch.object(codex_net_wsl, "_remove_slice_entries")
    @mock.patch.object(codex_net_wsl, "_run_nft")
    @mock.patch.object(codex_net_wsl, "prepare_slice_units")
    @mock.patch.object(codex_net_wsl, "nft_socket_support_report")
    def test_apply_nft_rules_rolls_back_slices_when_validation_fails(
        self,
        mock_nft_socket_support_report: mock.Mock,
        mock_prepare_slice_units: mock.Mock,
        mock_run_nft: mock.Mock,
        mock_remove_slice_entries: mock.Mock,
    ) -> None:
        prepared_slices = [
            {
                "mode": "systemd_user",
                "slice_name": "app-codex-net-registries.slice",
                "unit_path": "/tmp/app-codex-net-registries.slice",
            }
        ]
        compiled = {
            "nft_path": "/tmp/network_profiles.compiled.nft",
            "manifest": {
                "backend_linux_wsl_nft": {"nft_table_name": "codex_hardening"},
            },
        }
        mock_nft_socket_support_report.return_value = {"ok": True, "detail": "CONFIG_NFT_SOCKET=y"}
        mock_prepare_slice_units.return_value = prepared_slices
        mock_run_nft.return_value = subprocess.CompletedProcess(
            args=["nft", "-c", "-f", "/tmp/network_profiles.compiled.nft"],
            returncode=1,
            stdout="",
            stderr="validation failed",
        )

        with self.assertRaisesRegex(BackendError, "nftables syntax validation failed"):
            apply_nft_rules(compiled, use_sudo=False)

        mock_remove_slice_entries.assert_called_once_with(prepared_slices, False)

    @mock.patch.object(codex_net_wsl, "prepare_slice_units")
    @mock.patch.object(codex_net_wsl, "nft_socket_support_report")
    def test_apply_nft_rules_fails_early_without_nft_socket_support(
        self,
        mock_nft_socket_support_report: mock.Mock,
        mock_prepare_slice_units: mock.Mock,
    ) -> None:
        mock_nft_socket_support_report.return_value = {
            "ok": False,
            "detail": "CONFIG_NFT_SOCKET is not set in this kernel.",
        }
        compiled = {
            "nft_path": "/tmp/network_profiles.compiled.nft",
            "manifest": {
                "backend_linux_wsl_nft": {"nft_table_name": "codex_hardening"},
            },
        }

        with self.assertRaisesRegex(BackendError, "CONFIG_NFT_SOCKET"):
            apply_nft_rules(compiled, use_sudo=False)

        mock_prepare_slice_units.assert_not_called()


if __name__ == "__main__":
    unittest.main()
