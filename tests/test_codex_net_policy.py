import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from codex_net_policy import (  # noqa: E402
    NetworkIntent,
    PolicyError,
    clear_backend_override,
    collect_network_requests,
    inspect_network_intent,
    load_network_profiles,
    persist_backend_selection,
    select_profile_for_command,
    validate_command_for_profile,
    write_backend_override,
)


CONFIG = load_network_profiles(ROOT / "policies" / "network_profiles.toml")


class CollectNetworkRequestsTests(unittest.TestCase):
    def test_collects_requests_from_nested_shell_wrappers(self) -> None:
        requests = collect_network_requests("bash -lc 'curl https://github.com && git clone https://github.com/openai/codex.git'")
        self.assertEqual([request.tool for request in requests], ["curl", "git"])
        self.assertEqual([request.host for request in requests], ["github.com", "github.com"])

    def test_collects_requests_from_env_wrapper(self) -> None:
        requests = collect_network_requests("env FOO=bar curl https://github.com")
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].tool, "curl")
        self.assertEqual(requests[0].host, "github.com")

    def test_collects_requests_across_command_segments(self) -> None:
        fixtures = {
            "&&": "curl https://github.com && git clone https://github.com/openai/codex.git",
            "&& without spaces": "curl https://github.com&&git clone https://github.com/openai/codex.git",
            ";": "curl https://github.com; git clone https://github.com/openai/codex.git",
            "; without spaces": "curl https://github.com;git clone https://github.com/openai/codex.git",
        }
        for separator, command in fixtures.items():
            with self.subTest(separator=separator):
                requests = collect_network_requests(command)
                self.assertEqual([request.tool for request in requests], ["curl", "git"])


class SelectProfileForCommandTests(unittest.TestCase):
    def test_returns_none_for_ordinary_offline_commands(self) -> None:
        self.assertIsNone(select_profile_for_command(CONFIG, "ls"))

    def test_uses_specific_profile_mapping_when_available(self) -> None:
        self.assertEqual(select_profile_for_command(CONFIG, "git fetch origin"), "git_readonly")

    def test_falls_back_to_custom_only_for_unmapped_network_commands(self) -> None:
        profile = select_profile_for_command(CONFIG, "git push git@github.com:openai/codex.git")
        self.assertEqual(profile, "custom")

    def test_covers_additional_package_manager_and_git_flows(self) -> None:
        fixtures = {
            "uv sync": "registries",
            "uv add openai": "registries",
            "pip download openai": "registries",
            "npm ci": "registries",
            "npm update": "registries",
            "pnpm install": "registries",
            "pnpm update": "registries",
            "yarn install": "registries",
            "yarn add react": "registries",
            "go get example.com/mod": "registries",
            "cargo install ripgrep": "registries",
            "cargo update": "registries",
            "git ls-remote origin": "git_readonly",
            "git pull origin main": "git_readonly",
        }
        for command, expected in fixtures.items():
            with self.subTest(command=command):
                self.assertEqual(select_profile_for_command(CONFIG, command), expected)


class InspectNetworkIntentTests(unittest.TestCase):
    def test_returns_none_for_offline_command(self) -> None:
        self.assertIsNone(inspect_network_intent(CONFIG, "ls"))

    def test_classifies_explicit_intent(self) -> None:
        intent = inspect_network_intent(CONFIG, "curl https://github.com")
        self.assertIsInstance(intent, NetworkIntent)
        self.assertEqual(intent.kind, "explicit")
        self.assertEqual(intent.profile, "registries")
        self.assertEqual([request.host for request in intent.requests], ["github.com"])

    def test_classifies_implicit_intent(self) -> None:
        intent = inspect_network_intent(CONFIG, "npm ci")
        self.assertIsInstance(intent, NetworkIntent)
        self.assertEqual(intent.kind, "implicit")
        self.assertEqual(intent.profile, "registries")
        self.assertEqual(intent.requests, [])

    def test_preserves_dynamic_request_issue_through_nested_wrappers(self) -> None:
        intent = inspect_network_intent(CONFIG, "bash -lc 'env URL=https://github.com curl $URL'")
        self.assertIsInstance(intent, NetworkIntent)
        self.assertEqual(intent.kind, "explicit")
        self.assertEqual(intent.profile, "registries")
        self.assertEqual(len(intent.requests), 1)
        self.assertIn("dynamic and cannot be verified", intent.requests[0].issue or "")


class ValidateCommandForProfileTests(unittest.TestCase):
    def test_allows_explicit_approved_remote_command(self) -> None:
        validate_command_for_profile("curl https://github.com", "registries", CONFIG)

    def test_blocks_disallowed_remote_domain(self) -> None:
        with self.assertRaisesRegex(PolicyError, "does not allow `curl` destination"):
            validate_command_for_profile("curl https://evil.example", "registries", CONFIG)

    def test_blocks_implicit_remote_command_in_hook_only_mode(self) -> None:
        with self.assertRaisesRegex(PolicyError, "hook_only backend can only validate"):
            validate_command_for_profile("git fetch origin", "git_readonly", CONFIG)

    def test_allows_implicit_remote_command_on_linux_backend(self) -> None:
        linux_config = dict(CONFIG)
        linux_config["backend"] = "linux_wsl_nft"
        validate_command_for_profile("npm ci", "registries", linux_config)

    def test_allows_local_dev_port(self) -> None:
        validate_command_for_profile("curl http://localhost:8080", "dev_local", CONFIG)

    def test_blocks_local_port_outside_profile(self) -> None:
        with self.assertRaisesRegex(PolicyError, "does not allow localhost TCP port 9999"):
            validate_command_for_profile("curl http://localhost:9999", "dev_local", CONFIG)

    def test_blocks_approval_required_profile_when_enforced(self) -> None:
        with self.assertRaisesRegex(PolicyError, "require_approval = true"):
            validate_command_for_profile(
                "curl https://github.com",
                "registries",
                CONFIG,
                enforce_require_approval=True,
            )

    def test_relaxed_network_allows_any_domain_on_common_ports(self) -> None:
        validate_command_for_profile("curl https://example.com", "relaxed_network", CONFIG)
        validate_command_for_profile("ssh git@github.com", "relaxed_network", CONFIG)


class BackendSelectionTests(unittest.TestCase):
    def test_load_network_profiles_applies_temporary_backend_override(self) -> None:
        with TemporaryDirectory() as tmpdir:
            override_path = Path(tmpdir) / "backend_override.json"
            previous = os.environ.get("CODEX_NET_BACKEND_OVERRIDE_PATH")
            os.environ["CODEX_NET_BACKEND_OVERRIDE_PATH"] = str(override_path)
            self.addCleanup(
                lambda: os.environ.__setitem__("CODEX_NET_BACKEND_OVERRIDE_PATH", previous)
                if previous is not None
                else os.environ.pop("CODEX_NET_BACKEND_OVERRIDE_PATH", None)
            )

            write_backend_override("linux_wsl_netns")
            config = load_network_profiles(ROOT / "policies" / "network_profiles.toml")
            self.assertEqual(config["configured_backend"], "hook_only")
            self.assertEqual(config["backend_override"], "linux_wsl_netns")
            self.assertEqual(config["backend"], "linux_wsl_netns")

            clear_backend_override()
            config = load_network_profiles(ROOT / "policies" / "network_profiles.toml")
            self.assertEqual(config["backend_override"], None)
            self.assertEqual(config["backend"], "hook_only")

    def test_persist_backend_selection_rewrites_policy_backend_line(self) -> None:
        with TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "network_profiles.toml"
            policy_path.write_text('backend = "hook_only"\ndefault_profile = "offline"\n[profiles.offline]\nallowed_domains=[]\n')

            previous_backend, selected_backend = persist_backend_selection(policy_path, "linux_wsl_netns")

            self.assertEqual(previous_backend, "hook_only")
            self.assertEqual(selected_backend, "linux_wsl_netns")
            self.assertIn('backend = "linux_wsl_netns"', policy_path.read_text())


if __name__ == "__main__":
    unittest.main()
