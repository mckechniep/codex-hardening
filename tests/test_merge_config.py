import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from merge_config import merge_config  # noqa: E402


class MergeConfigTests(unittest.TestCase):
    def test_merge_config_adds_missing_managed_settings(self) -> None:
        existing_text = 'model = "test-model"\n'
        existing_data = {"model": "test-model"}
        desired = {
            "approval_policy": "on-request",
            "sandbox_mode": "workspace-write",
            "history": {"persistence": "none"},
            "features": {"hooks": True},
        }

        rendered, changes, conflicts = merge_config(existing_text, existing_data, desired)

        self.assertIn('model = "test-model"', rendered)
        self.assertIn('approval_policy = "on-request"', rendered)
        self.assertIn('sandbox_mode = "workspace-write"', rendered)
        self.assertIn("[history]", rendered)
        self.assertIn('persistence = "none"', rendered)
        self.assertIn("[features]", rendered)
        self.assertIn("hooks = true", rendered)
        self.assertTrue(changes)
        self.assertEqual(conflicts, [])

    def test_merge_config_repairs_unsafe_managed_values(self) -> None:
        existing_text = '\n'.join(
            [
                'approval_policy = "never"',
                'sandbox_mode = "danger-full-access"',
                "",
                "[sandbox_workspace_write]",
                "network_access = true",
                "",
                "[features]",
                "codex_hooks = false",
                "",
            ]
        )
        existing_data = {
            "approval_policy": "never",
            "sandbox_mode": "danger-full-access",
            "sandbox_workspace_write": {"network_access": True},
            "features": {"codex_hooks": False},
        }
        desired = {
            "approval_policy": "on-request",
            "sandbox_mode": "workspace-write",
            "sandbox_workspace_write": {"network_access": False},
            "features": {"hooks": True},
        }

        rendered, changes, conflicts = merge_config(existing_text, existing_data, desired)

        self.assertIn('approval_policy = "on-request"', rendered)
        self.assertIn('sandbox_mode = "workspace-write"', rendered)
        self.assertIn("network_access = false", rendered)
        self.assertIn("hooks = true", rendered)
        self.assertNotIn("codex_hooks", rendered)
        self.assertEqual(conflicts, [])
        self.assertEqual(len(changes), 5)

    def test_merge_config_preserves_stricter_or_unrecognized_good_values(self) -> None:
        existing_text = '\n'.join(
            [
                'sandbox_mode = "read-only"',
                "web_search = false",
                "",
                "[shell_environment_policy]",
                'inherit = "none"',
                "",
            ]
        )
        existing_data = {
            "sandbox_mode": "read-only",
            "web_search": False,
            "shell_environment_policy": {"inherit": "none"},
        }
        desired = {
            "sandbox_mode": "workspace-write",
            "web_search": "cached",
            "shell_environment_policy": {"inherit": "core"},
        }

        rendered, changes, conflicts = merge_config(existing_text, existing_data, desired)

        self.assertIn('sandbox_mode = "read-only"', rendered)
        self.assertIn("web_search = false", rendered)
        self.assertIn('inherit = "none"', rendered)
        self.assertEqual(changes, [])
        self.assertEqual(len(conflicts), 3)

    def test_merge_config_prunes_secret_like_environment_names_and_adds_baseline(self) -> None:
        existing_text = '\n'.join(
            [
                "[shell_environment_policy]",
                'include_only = ["HOME", "OPENAI_API_KEY", "CUSTOM_FLAG"]',
                "",
            ]
        )
        existing_data = {
            "shell_environment_policy": {
                "include_only": ["HOME", "OPENAI_API_KEY", "CUSTOM_FLAG"],
            },
        }
        desired = {
            "shell_environment_policy": {
                "include_only": ["HOME", "PATH", "LANG"],
            }
        }

        rendered, changes, conflicts = merge_config(existing_text, existing_data, desired)

        self.assertIn('include_only = ["HOME", "CUSTOM_FLAG", "PATH", "LANG"]', rendered)
        self.assertNotIn("OPENAI_API_KEY", rendered)
        self.assertTrue(any("removed secret-like entries" in change for change in changes))
        self.assertEqual(conflicts, [])


if __name__ == "__main__":
    unittest.main()
