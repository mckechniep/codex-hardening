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
            "features": {"codex_hooks": True},
        }

        rendered, changes, conflicts = merge_config(existing_text, existing_data, desired)

        self.assertIn('model = "test-model"', rendered)
        self.assertIn('approval_policy = "on-request"', rendered)
        self.assertIn('sandbox_mode = "workspace-write"', rendered)
        self.assertIn("[history]", rendered)
        self.assertIn('persistence = "none"', rendered)
        self.assertIn("[features]", rendered)
        self.assertIn("codex_hooks = true", rendered)
        self.assertTrue(changes)
        self.assertEqual(conflicts, [])

    def test_merge_config_preserves_conflicting_existing_values(self) -> None:
        existing_text = '\n'.join(
            [
                'approval_policy = "never"',
                "",
                "[features]",
                "codex_hooks = false",
                "",
            ]
        )
        existing_data = {
            "approval_policy": "never",
            "features": {"codex_hooks": False},
        }
        desired = {
            "approval_policy": "on-request",
            "features": {"codex_hooks": True},
        }

        rendered, changes, conflicts = merge_config(existing_text, existing_data, desired)

        self.assertIn('approval_policy = "never"', rendered)
        self.assertIn("codex_hooks = false", rendered)
        self.assertEqual(changes, [])
        self.assertEqual(len(conflicts), 2)


if __name__ == "__main__":
    unittest.main()
