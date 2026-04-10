import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from merge_hooks import (  # noqa: E402
    load_existing,
    load_template,
    merge_hook_lists,
    merge_hooks,
    merge_matchers,
)


class MergeHookListsTests(unittest.TestCase):
    def test_replaces_matching_hook_and_appends_new_hook(self) -> None:
        existing = [
            {"type": "command", "command": "python old.py", "timeout": 5},
            {"type": "command", "command": "python keep.py", "timeout": 5},
        ]
        incoming = [
            {"type": "command", "command": "python old.py", "timeout": 10},
            {"type": "command", "command": "python new.py", "timeout": 15},
        ]

        merged = merge_hook_lists(existing, incoming)

        self.assertEqual(
            merged,
            [
                {"type": "command", "command": "python old.py", "timeout": 10},
                {"type": "command", "command": "python keep.py", "timeout": 5},
                {"type": "command", "command": "python new.py", "timeout": 15},
            ],
        )


class MergeMatchersTests(unittest.TestCase):
    def test_merges_matching_entries_and_preserves_unrelated_matchers(self) -> None:
        existing = [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "python old.py"}], "extra": "keep"},
            {"matcher": "Edit", "hooks": [{"type": "command", "command": "python edit.py"}]},
        ]
        incoming = [
            {
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "python new.py"}],
                "statusMessage": "Checking bash hooks",
            }
        ]

        merged = merge_matchers(existing, incoming)

        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[0]["matcher"], "Bash")
        self.assertEqual(
            merged[0]["hooks"],
            [
                {"type": "command", "command": "python old.py"},
                {"type": "command", "command": "python new.py"},
            ],
        )
        self.assertEqual(merged[0]["extra"], "keep")
        self.assertEqual(merged[0]["statusMessage"], "Checking bash hooks")
        self.assertEqual(merged[1]["matcher"], "Edit")


class MergeHooksTests(unittest.TestCase):
    def test_merges_event_lists_without_dropping_other_events(self) -> None:
        existing = {
            "hooks": {
                "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "python old.py"}]}],
                "PostToolUse": [{"matcher": "Write", "hooks": [{"type": "command", "command": "python post.py"}]}],
            }
        }
        incoming = {
            "hooks": {
                "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "python new.py"}]}]
            }
        }

        merged = merge_hooks(existing, incoming)

        self.assertIn("PostToolUse", merged["hooks"])
        self.assertEqual(
            merged["hooks"]["PreToolUse"][0]["hooks"],
            [
                {"type": "command", "command": "python old.py"},
                {"type": "command", "command": "python new.py"},
            ],
        )


class TemplateAndExistingLoadTests(unittest.TestCase):
    def test_load_template_replaces_home_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            template_path = Path(tmpdir) / "hooks.json.template"
            template_path.write_text(
                json.dumps(
                    {
                        "hooks": {
                            "PreToolUse": [
                                {
                                    "matcher": "Bash",
                                    "hooks": [{"type": "command", "command": "__HOME__/.codex/hook.py"}],
                                }
                            ]
                        }
                    }
                )
            )

            loaded = load_template(template_path, Path("/tmp/test-home"))
            command = loaded["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            self.assertEqual(command, "/tmp/test-home/.codex/hook.py")

    def test_load_existing_initializes_missing_hooks_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            existing_path = Path(tmpdir) / "hooks.json"
            existing_path.write_text(json.dumps({"version": 1}))

            loaded = load_existing(existing_path)

            self.assertEqual(loaded, {"version": 1, "hooks": {}})


if __name__ == "__main__":
    unittest.main()
