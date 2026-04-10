import json
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
INSTALL_SCRIPT = ROOT / "scripts" / "install.sh"


class InstallScriptTests(unittest.TestCase):
    def test_install_script_copies_assets_and_merges_hooks(self) -> None:
        with TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            codex_dir = home / ".codex"
            (codex_dir / "hooks").mkdir(parents=True)
            (codex_dir / "policies").mkdir(parents=True)

            (codex_dir / "config.toml").write_text('model = "test-model"\n')
            (codex_dir / "policies" / "network_profiles.toml").write_text("# keep me\nbackend = \"hook_only\"\n")
            (codex_dir / "hooks.json").write_text(
                json.dumps(
                    {
                        "hooks": {
                            "PostToolUse": [
                                {
                                    "matcher": "Write",
                                    "hooks": [{"type": "command", "command": "python keep.py"}],
                                }
                            ]
                        }
                    }
                )
            )

            env = dict(os.environ)
            env["HOME"] = str(home)

            result = subprocess.run(
                ["bash", str(INSTALL_SCRIPT)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((codex_dir / "hooks" / "block_destructive.py").exists())
            self.assertTrue((codex_dir / "hooks" / "block_network_egress.py").exists())
            self.assertTrue((codex_dir / "rules" / "default.rules").exists())
            self.assertTrue((codex_dir / "scripts" / "codex-net").exists())
            self.assertTrue((codex_dir / "scripts" / "codex_net_netns.py").exists())
            self.assertFalse((codex_dir / "policies" / "network_allowlist.json").exists())
            self.assertEqual((codex_dir / "config.toml").read_text(), 'model = "test-model"\n')
            self.assertEqual(
                (codex_dir / "policies" / "network_profiles.toml").read_text(),
                "# keep me\nbackend = \"hook_only\"\n",
            )

            hooks = json.loads((codex_dir / "hooks.json").read_text())
            self.assertIn("PreToolUse", hooks["hooks"])
            self.assertIn("PostToolUse", hooks["hooks"])

            bash_entries = [entry for entry in hooks["hooks"]["PreToolUse"] if entry.get("matcher") == "Bash"]
            self.assertEqual(len(bash_entries), 1)
            commands = [hook["command"] for hook in bash_entries[0]["hooks"]]
            self.assertIn(f"/usr/bin/python3 {home}/.codex/hooks/block_destructive.py", commands)
            self.assertIn(f"/usr/bin/python3 {home}/.codex/hooks/block_network_egress.py", commands)

            backups = list((codex_dir / "backups").glob("codex-hardening-*"))
            self.assertEqual(len(backups), 1)
            self.assertNotIn("network_allowlist.json", result.stdout)


if __name__ == "__main__":
    unittest.main()
