import json
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "codex-net"
POLICY = ROOT / "policies" / "network_profiles.toml"


def cli_env(tmpdir: str) -> dict[str, str]:
    env = dict(os.environ)
    env["CODEX_NET_POLICY_PATH"] = str(POLICY)
    env["CODEX_NET_STATE_PATH"] = str(Path(tmpdir) / "backend_state.json")
    env["CODEX_NET_COMPILED_DIR"] = str(Path(tmpdir) / "compiled")
    return env


class CodexNetCliTests(unittest.TestCase):
    def test_list_profiles_prints_expected_entries(self) -> None:
        with TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [str(CLI), "list-profiles"],
                cwd=ROOT,
                env=cli_env(tmpdir),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("offline (default): No remote network access.", result.stdout)
            self.assertIn("registries: Common package registries and source hosts.", result.stdout)

    def test_show_config_prints_loaded_policy_path(self) -> None:
        with TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [str(CLI), "show-config"],
                cwd=ROOT,
                env=cli_env(tmpdir),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f"path: {POLICY}", result.stdout)
            self.assertIn("backend: hook_only", result.stdout)
            self.assertIn("default_profile: offline", result.stdout)

    def test_backend_status_json_reports_missing_state(self) -> None:
        with TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [str(CLI), "backend-status", "--json"],
                cwd=ROOT,
                env=cli_env(tmpdir),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertFalse(payload["present"])
            self.assertFalse(payload["ready"])
            self.assertIn("No backend state file has been recorded yet.", payload["issues"])

    def test_doctor_json_reports_backend_readiness(self) -> None:
        with TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [str(CLI), "doctor", "--json"],
                cwd=ROOT,
                env=cli_env(tmpdir),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertIn("backend_readiness", payload)
            self.assertIn("linux_wsl_nft", payload["backend_readiness"])
            self.assertIn("linux_wsl_netns", payload["backend_readiness"])
            self.assertIn("netns_checks", payload)

    def test_exec_requires_wrapped_command(self) -> None:
        with TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [str(CLI), "exec", "--profile", "offline"],
                cwd=ROOT,
                env=cli_env(tmpdir),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("requires a wrapped command", result.stderr)

    def test_exec_rejects_unknown_profile(self) -> None:
        with TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [str(CLI), "exec", "--profile", "missing", "--", "curl", "https://github.com"],
                cwd=ROOT,
                env=cli_env(tmpdir),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("Unknown network profile `missing`.", result.stderr)

    def test_exec_blocks_implicit_remote_command_in_hook_only_backend(self) -> None:
        with TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [str(CLI), "exec", "--profile", "git_readonly", "--", "git", "fetch", "origin"],
                cwd=ROOT,
                env=cli_env(tmpdir),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("hook_only backend can only validate commands with explicit network targets", result.stderr)

    def test_exec_blocks_package_manager_command_in_hook_only_backend(self) -> None:
        with TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [str(CLI), "exec", "--profile", "registries", "--", "npm", "ci"],
                cwd=ROOT,
                env=cli_env(tmpdir),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("hook_only backend can only validate commands with explicit network targets", result.stderr)


if __name__ == "__main__":
    unittest.main()
