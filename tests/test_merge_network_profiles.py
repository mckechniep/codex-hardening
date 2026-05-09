import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from merge_network_profiles import merge_network_profiles  # noqa: E402


class MergeNetworkProfilesTests(unittest.TestCase):
    def test_merge_network_profiles_adds_missing_sections_and_mappings(self) -> None:
        existing_text = '# keep me\nbackend = "hook_only"\n'
        existing_data = {"backend": "hook_only"}
        desired = {
            "backend": "hook_only",
            "default_profile": "offline",
            "profiles": {
                "offline": {
                    "description": "No remote network access.",
                    "allow_localhost": True,
                    "allowed_domains": [],
                    "allowed_tcp_ports": [],
                    "allowed_udp_ports": [],
                    "require_approval": False,
                }
            },
            "command_profiles": {"npm install": "registries"},
        }

        rendered, changes, conflicts = merge_network_profiles(existing_text, existing_data, desired)

        self.assertIn('# keep me\nbackend = "hook_only"', rendered)
        self.assertIn('default_profile = "offline"', rendered)
        self.assertIn("[profiles.offline]", rendered)
        self.assertIn('description = "No remote network access."', rendered)
        self.assertIn("[command_profiles]", rendered)
        self.assertIn('"npm install" = "registries"', rendered)
        self.assertTrue(changes)
        self.assertEqual(conflicts, [])

    def test_merge_network_profiles_extends_stock_profile_lists(self) -> None:
        existing_text = "\n".join(
            [
                "[profiles.registries]",
                'description = "Common package registries and source hosts."',
                "allow_localhost = true",
                'allowed_domains = ["github.com"]',
                "allowed_tcp_ports = [443]",
                "allowed_udp_ports = []",
                "require_approval = true",
                "",
            ]
        )
        existing_data = {
            "profiles": {
                "registries": {
                    "description": "Common package registries and source hosts.",
                    "allow_localhost": True,
                    "allowed_domains": ["github.com"],
                    "allowed_tcp_ports": [443],
                    "allowed_udp_ports": [],
                    "require_approval": True,
                }
            }
        }
        desired = {
            "profiles": {
                "registries": {
                    "description": "Common package registries and source hosts.",
                    "allow_localhost": True,
                    "allowed_domains": ["github.com", "registry.npmjs.org"],
                    "allowed_tcp_ports": [443],
                    "allowed_udp_ports": [53],
                    "require_approval": True,
                }
            }
        }

        rendered, changes, conflicts = merge_network_profiles(existing_text, existing_data, desired)

        self.assertIn('allowed_domains = ["github.com", "registry.npmjs.org"]', rendered)
        self.assertIn("allowed_udp_ports = [53]", rendered)
        self.assertIn("extended [profiles.registries] allowed_domains with missing shipped entries", changes)
        self.assertIn("extended [profiles.registries] allowed_udp_ports with missing shipped entries", changes)
        self.assertEqual(conflicts, [])

    def test_merge_network_profiles_preserves_conflicting_existing_values(self) -> None:
        existing_text = "\n".join(
            [
                'backend = "linux_wsl_netns"',
                "",
                "[profiles.registries]",
                "require_approval = false",
                "",
            ]
        )
        existing_data = {
            "backend": "linux_wsl_netns",
            "profiles": {
                "registries": {
                    "require_approval": False,
                }
            },
        }
        desired = {
            "backend": "hook_only",
            "profiles": {
                "registries": {
                    "require_approval": True,
                }
            },
        }

        rendered, changes, conflicts = merge_network_profiles(existing_text, existing_data, desired)

        self.assertIn('backend = "linux_wsl_netns"', rendered)
        self.assertIn("require_approval = false", rendered)
        self.assertEqual(changes, [])
        self.assertEqual(len(conflicts), 2)


if __name__ == "__main__":
    unittest.main()
