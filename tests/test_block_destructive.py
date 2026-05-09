import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "hooks" / "block_destructive.py"


def run_hook(command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps({"tool_input": {"command": command}}),
        text=True,
        capture_output=True,
        check=False,
    )


class BlockDestructiveTests(unittest.TestCase):
    def test_safe_command_is_allowed(self) -> None:
        result = run_hook("ls")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")

    def test_hard_block_pattern_is_denied(self) -> None:
        result = run_hook("rm -rf /")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Recursive deletion at filesystem root", result.stderr)

    def test_root_glob_delete_is_denied(self) -> None:
        result = run_hook("rm -rf /*")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Recursive deletion at filesystem root", result.stderr)

    def test_home_env_delete_is_denied(self) -> None:
        result = run_hook("rm -rf $HOME")
        self.assertEqual(result.returncode, 2)
        self.assertIn("home directory", result.stderr)

    def test_absolute_home_directory_delete_is_denied(self) -> None:
        result = run_hook("rm -rf /home/mckec")
        self.assertEqual(result.returncode, 2)
        self.assertIn("home directory", result.stderr)

    def test_manual_only_pattern_is_denied(self) -> None:
        result = run_hook("git reset --hard HEAD~1")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Destructive Git resets are manual-only.", result.stderr)

    def test_nested_shell_manual_only_pattern_is_denied(self) -> None:
        result = run_hook("bash -lc 'sudo apt update'")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Privilege escalation is manual-only.", result.stderr)


if __name__ == "__main__":
    unittest.main()
