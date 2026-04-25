import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from merge_developer_instructions import merge_developer_instructions  # noqa: E402


class MergeDeveloperInstructionsTests(unittest.TestCase):
    def test_adds_missing_developer_instructions_before_tables(self) -> None:
        rendered, action = merge_developer_instructions(
            'model = "test-model"\n\n[features]\ncodex_hooks = true\n',
            {"model": "test-model", "features": {"codex_hooks": True}},
            "Use codex-net.",
        )

        self.assertEqual(action, "added")
        self.assertIn('model = "test-model"', rendered)
        self.assertLess(rendered.index("developer_instructions"), rendered.index("[features]"))
        self.assertIn("BEGIN codex-hardening network guidance", rendered)
        self.assertIn("Use codex-net.", rendered)

    def test_appends_to_existing_developer_instructions(self) -> None:
        rendered, action = merge_developer_instructions(
            'developer_instructions = "Keep this."\n',
            {"developer_instructions": "Keep this."},
            "Use codex-net.",
        )

        self.assertEqual(action, "appended")
        self.assertIn("Keep this.", rendered)
        self.assertIn("Use codex-net.", rendered)

    def test_is_idempotent_when_managed_block_already_exists(self) -> None:
        existing = (
            'developer_instructions = """\n'
            "# BEGIN codex-hardening network guidance\n"
            "Use codex-net.\n"
            "# END codex-hardening network guidance\n"
            '"""\n'
        )
        rendered, action = merge_developer_instructions(
            existing,
            {
                "developer_instructions": (
                    "# BEGIN codex-hardening network guidance\n"
                    "Use codex-net.\n"
                    "# END codex-hardening network guidance\n"
                )
            },
            "Use codex-net.",
        )

        self.assertEqual(action, "already_present")
        self.assertEqual(rendered.count("BEGIN codex-hardening network guidance"), 1)


if __name__ == "__main__":
    unittest.main()
