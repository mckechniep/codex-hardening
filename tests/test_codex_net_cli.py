import json
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "codex-net"
POLICY = ROOT / "policies" / "network_profiles.toml"


def cli_env(tmpdir: str, policy_path: Path | None = None) -> dict[str, str]:
    env = dict(os.environ)
    env["CODEX_NET_POLICY_PATH"] = str(policy_path or POLICY)
    env["CODEX_NET_STATE_PATH"] = str(Path(tmpdir) / "backend_state.json")
    env["CODEX_NET_COMPILED_DIR"] = str(Path(tmpdir) / "compiled")
    env["CODEX_NET_BACKEND_OVERRIDE_PATH"] = str(Path(tmpdir) / "backend_override.json")
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
            self.assertIn("approved: User-approved unattended destinations and commands.", result.stdout)
            self.assertIn("registries: Common package registries and source hosts.", result.stdout)
            self.assertIn("relaxed_network: Relaxed network access for day-to-day personal use.", result.stdout)

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
            self.assertIn("configured_backend: hook_only", result.stdout)
            self.assertIn("backend_override: None", result.stdout)
            self.assertIn("backend: hook_only", result.stdout)
            self.assertIn("default_profile: offline", result.stdout)

    def test_backend_set_temporary_override_is_reflected_in_show_config(self) -> None:
        with TemporaryDirectory() as tmpdir:
            env = cli_env(tmpdir)
            set_result = subprocess.run(
                [str(CLI), "backend-set", "linux_wsl_netns"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(set_result.returncode, 0, set_result.stderr)
            self.assertIn("selection: temporary", set_result.stdout)

            show_result = subprocess.run(
                [str(CLI), "show-config"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(show_result.returncode, 0, show_result.stderr)
            self.assertIn("configured_backend: hook_only", show_result.stdout)
            self.assertIn("backend_override: linux_wsl_netns", show_result.stdout)
            self.assertIn("backend: linux_wsl_netns", show_result.stdout)

            clear_result = subprocess.run(
                [str(CLI), "backend-clear"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(clear_result.returncode, 0, clear_result.stderr)
            self.assertIn("cleared: true", clear_result.stdout)

    def test_use_alias_sets_and_clears_common_backend_names(self) -> None:
        with TemporaryDirectory() as tmpdir:
            env = cli_env(tmpdir)
            set_result = subprocess.run(
                [str(CLI), "use", "netns"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(set_result.returncode, 0, set_result.stderr)
            self.assertIn("backend: linux_wsl_netns", set_result.stdout)

            show_result = subprocess.run(
                [str(CLI), "show-config"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(show_result.returncode, 0, show_result.stderr)
            self.assertIn("backend_override: linux_wsl_netns", show_result.stdout)

            clear_result = subprocess.run(
                [str(CLI), "use", "default"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(clear_result.returncode, 0, clear_result.stderr)
            self.assertIn("cleared: true", clear_result.stdout)

    def test_use_default_rejects_persist_flag(self) -> None:
        with TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [str(CLI), "use", "default", "--persist"],
                cwd=ROOT,
                env=cli_env(tmpdir),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("`codex-net use default` returns to the configured backend", result.stderr)

    def test_make_default_persists_backend_selection(self) -> None:
        with TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "network_profiles.toml"
            policy_path.write_text(POLICY.read_text())
            result = subprocess.run(
                [str(CLI), "make-default", "hook_only"],
                cwd=ROOT,
                env=cli_env(tmpdir, policy_path),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("selection: persistent", result.stdout)
            self.assertIn('backend = "hook_only"', policy_path.read_text())

    def test_backend_info_prints_guided_choices(self) -> None:
        with TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [str(CLI), "backend-info"],
                cwd=ROOT,
                env=cli_env(tmpdir),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("backend_choices:", result.stdout)
            self.assertIn("choose: ~/.codex/scripts/codex-net use hook_only", result.stdout)
            self.assertIn("choose: ~/.codex/scripts/codex-net use netns --prepare --sudo", result.stdout)
            self.assertIn("rollback:", result.stdout)

    def test_setup_print_only_prints_tailored_menu_without_changing_backend(self) -> None:
        with TemporaryDirectory() as tmpdir:
            env = cli_env(tmpdir)
            result = subprocess.run(
                [str(CLI), "setup", "--print-only"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Codex hardening backend setup", result.stdout)
            self.assertIn("current_backend: hook_only", result.stdout)
            self.assertIn("Choose a mode:", result.stdout)
            self.assertIn("Recommended for this host", result.stdout)
            self.assertIn("Light hook-only mode", result.stdout)
            self.assertIn("Strict WSL namespace mode", result.stdout)
            self.assertIn("No changes made.", result.stdout)
            self.assertFalse((Path(tmpdir) / "backend_override.json").exists())

    def test_approve_adds_domain_and_command_mapping_with_inferred_port(self) -> None:
        with TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "network_profiles.toml"
            policy_path.write_text(POLICY.read_text())
            result = subprocess.run(
                [str(CLI), "approve", "https://api.mycompany.com/v1", "--command", "mycli sync"],
                cwd=ROOT,
                env=cli_env(tmpdir, policy_path),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("profile: approved", result.stdout)
            self.assertIn("domain: api.mycompany.com", result.stdout)
            self.assertIn("tcp_ports: 443", result.stdout)
            self.assertIn("command_profile: mycli sync -> approved", result.stdout)
            policy_text = policy_path.read_text()
            self.assertIn('allowed_domains = ["api.mycompany.com"]', policy_text)
            self.assertIn("allowed_tcp_ports = [443]", policy_text)
            self.assertIn("require_approval = false", policy_text)
            self.assertIn('"mycli sync" = "approved"', policy_text)

    def test_approve_infers_ssh_port_for_git_ssh_target(self) -> None:
        with TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "network_profiles.toml"
            policy_path.write_text(POLICY.read_text())
            result = subprocess.run(
                [str(CLI), "approve", "git@github.com:example/repo.git", "--command", "git ls-remote"],
                cwd=ROOT,
                env=cli_env(tmpdir, policy_path),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("domain: github.com", result.stdout)
            self.assertIn("tcp_ports: 22", result.stdout)
            self.assertIn('allowed_tcp_ports = [22, 443]', policy_path.read_text())

    def test_autoexec_blocks_implicit_command_on_hook_only_backend_before_execution(self) -> None:
        with TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [str(CLI), "autoexec", "--", "git", "fetch", "origin"],
                cwd=ROOT,
                env=cli_env(tmpdir),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("hook_only backend can only validate commands with explicit network targets", result.stderr)

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

    def test_exec_blocks_uninspected_profile_command_in_hook_only_backend(self) -> None:
        with TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [str(CLI), "exec", "--profile", "relaxed_network", "--", "python3", "-c", "pass"],
                cwd=ROOT,
                env=cli_env(tmpdir),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("hook_only backend cannot inspect this command", result.stderr)

    def test_exec_blocks_approval_required_profile_before_execution(self) -> None:
        with TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [str(CLI), "exec", "--profile", "registries", "--", "curl", "https://github.com"],
                cwd=ROOT,
                env=cli_env(tmpdir),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("require_approval = true", result.stderr)


if __name__ == "__main__":
    unittest.main()
