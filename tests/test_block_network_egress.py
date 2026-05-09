import os
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "hooks" / "block_network_egress.py"
POLICY = ROOT / "policies" / "network_profiles.toml"
WRAPPER = ROOT / "scripts" / "codex-net"


def run_hook(command: str, *, policy_path: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["CODEX_NET_POLICY_PATH"] = str(policy_path or POLICY)
    return subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps({"tool_input": {"command": command}}),
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


class BlockNetworkEgressTests(unittest.TestCase):
    def test_non_network_command_is_not_blocked(self) -> None:
        result = run_hook("ls")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")

    def test_direct_network_command_requires_wrapper(self) -> None:
        result = run_hook("curl https://github.com")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Direct network commands must use codex-net.", result.stderr)

    def test_nested_shell_network_command_requires_wrapper(self) -> None:
        result = run_hook("bash -lc 'curl https://github.com'")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Direct network commands must use codex-net.", result.stderr)

    def test_dynamic_destination_is_rejected_without_wrapper_hint(self) -> None:
        result = run_hook("curl $URL")
        self.assertEqual(result.returncode, 2)
        self.assertIn("destination `$URL` is dynamic and cannot be verified", result.stderr)

    def test_wrapped_allowed_command_passes_validation(self) -> None:
        result = run_hook(f"{WRAPPER} exec --profile dev_local -- curl http://localhost:8080")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")

    def test_wrapped_uninspected_command_is_rejected_in_hook_only_mode(self) -> None:
        result = run_hook(f"{WRAPPER} exec --profile relaxed_network -- python3 -c pass")
        self.assertEqual(result.returncode, 2)
        self.assertIn("hook_only backend cannot inspect this command", result.stderr)

    def test_wrapped_approval_required_profile_is_rejected(self) -> None:
        result = run_hook(f"{WRAPPER} exec --profile registries -- curl https://github.com")
        self.assertEqual(result.returncode, 2)
        self.assertIn("require_approval = true", result.stderr)

    def test_destination_changing_curl_option_is_rejected(self) -> None:
        result = run_hook(
            f"{WRAPPER} exec --profile relaxed_network -- "
            "curl --connect-to github.com:443:evil.example:443 https://github.com"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("option `--connect-to`", result.stderr)

    def test_implicit_remote_command_is_blocked_in_hook_only_mode(self) -> None:
        result = run_hook("git fetch origin")
        self.assertEqual(result.returncode, 2)
        self.assertIn("hook_only backend cannot verify its actual destination", result.stderr)
        self.assertIn("linux_wsl_netns", result.stderr)

    def test_git_pull_is_treated_as_implicit_network_intent(self) -> None:
        result = run_hook("git pull origin main")
        self.assertEqual(result.returncode, 2)
        self.assertIn("implies network access and maps to profile `git_readonly`", result.stderr)

    def test_package_manager_command_is_treated_as_implicit_network_intent(self) -> None:
        result = run_hook("npm ci")
        self.assertEqual(result.returncode, 2)
        self.assertIn("implies network access and maps to profile `registries`", result.stderr)

    def test_package_manager_update_is_treated_as_implicit_network_intent(self) -> None:
        result = run_hook("npm update")
        self.assertEqual(result.returncode, 2)
        self.assertIn("implies network access and maps to profile `registries`", result.stderr)

    def test_missing_network_profile_config_is_denied(self) -> None:
        result = run_hook("curl https://github.com", policy_path=ROOT / "policies" / "missing.toml")
        self.assertEqual(result.returncode, 2)
        self.assertIn("No network profile config was found", result.stderr)
        self.assertIn("legacy network_allowlist.json path has been removed", result.stderr)


if __name__ == "__main__":
    unittest.main()
