import os
import sys
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import codex_net_wsl
from codex_net_wsl import backend_status_report, scope_launch_command, scope_runtime_report, write_backend_state


def sample_config(
    *,
    backend: str = "linux_wsl_nft",
    use_systemd_user: bool = True,
    allow_system_scope_fallback: bool = True,
) -> dict:
    return {
        "backend": backend,
        "backend_linux_wsl_nft": {
            "allow_system_scope_fallback": allow_system_scope_fallback,
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
        json_path.write_text("{}\n")
        nft_path.write_text("table inet codex_hardening {}\n")

        compiled = {
            "json_path": str(json_path),
            "nft_path": str(nft_path),
            "nft_sha256": sha256(nft_path.read_bytes()).hexdigest(),
            "manifest": {"backend": "linux_wsl_nft"},
        }
        write_backend_state(compiled, applied=True)

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


class ScopeLaunchCommandTests(unittest.TestCase):
    def test_scope_launch_command_uses_user_scope_by_default(self) -> None:
        command = scope_launch_command(
            "git_readonly",
            ["git", "clone", "https://github.com/openai/codex.git"],
            sample_config(),
        )
        self.assertEqual(command[:4], ["systemd-run", "--user", "--scope", "--unit=codex-net-git-readonly.scope"])

    def test_scope_launch_command_uses_sudo_for_system_scope(self) -> None:
        command = scope_launch_command(
            "registries",
            ["curl", "https://github.com"],
            sample_config(use_systemd_user=False),
        )
        self.assertEqual(command[:4], ["sudo", "systemd-run", "--scope", "--unit=codex-net-registries.scope"])

    def test_scope_launch_command_respects_explicit_mode_override(self) -> None:
        command = scope_launch_command(
            "registries",
            ["curl", "https://github.com"],
            sample_config(),
            mode="systemd_system",
        )
        self.assertEqual(command[:4], ["sudo", "systemd-run", "--scope", "--unit=codex-net-registries.scope"])


class ScopeRuntimeReportTests(unittest.TestCase):
    @mock.patch.object(codex_net_wsl, "system_scope_runtime_report")
    @mock.patch.object(codex_net_wsl, "default_scope_runtime_report")
    def test_scope_runtime_report_falls_back_to_system_scope(
        self,
        mock_user_report: mock.Mock,
        mock_system_report: mock.Mock,
    ) -> None:
        mock_user_report.return_value = {
            "ok": False,
            "mode": "systemd_user",
            "detail": "user bus unavailable",
        }
        mock_system_report.return_value = {
            "ok": True,
            "mode": "systemd_system",
            "detail": "system manager ok",
        }

        report = scope_runtime_report(sample_config())
        self.assertTrue(report["ok"])
        self.assertEqual(report["selected_mode"], "systemd_system")
        self.assertTrue(report["fallback_used"])
        self.assertIn("user bus unavailable", report["detail"])

    @mock.patch.object(codex_net_wsl, "system_scope_runtime_report")
    @mock.patch.object(codex_net_wsl, "default_scope_runtime_report")
    def test_scope_runtime_report_respects_disabled_fallback(
        self,
        mock_user_report: mock.Mock,
        mock_system_report: mock.Mock,
    ) -> None:
        mock_user_report.return_value = {
            "ok": False,
            "mode": "systemd_user",
            "detail": "user bus unavailable",
        }
        mock_system_report.return_value = {
            "ok": True,
            "mode": "systemd_system",
            "detail": "system manager ok",
        }

        report = scope_runtime_report(sample_config(allow_system_scope_fallback=False))
        self.assertFalse(report["ok"])
        self.assertEqual(report["selected_mode"], "systemd_user")
        self.assertFalse(report["fallback_used"])


if __name__ == "__main__":
    unittest.main()
