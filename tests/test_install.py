import json
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
INSTALL_SCRIPT = ROOT / "scripts" / "install.sh"
ENABLE_SCRIPT = ROOT / "scripts" / "enable.sh"


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
            self.assertTrue((codex_dir / "instructions" / "codex-hardening-model-instructions.md").exists())
            self.assertTrue((codex_dir / "rules" / "default.rules").exists())
            self.assertTrue((codex_dir / "scripts" / "codex-net").exists())
            self.assertTrue((codex_dir / "scripts" / "codex_net_netns.py").exists())
            self.assertTrue((codex_dir / "scripts" / "merge_config.py").exists())
            self.assertTrue((codex_dir / "scripts" / "merge_developer_instructions.py").exists())
            self.assertFalse((codex_dir / "policies" / "network_allowlist.json").exists())
            config_text = (codex_dir / "config.toml").read_text()
            self.assertIn('model = "test-model"\n', config_text)
            self.assertIn('approval_policy = "on-request"', config_text)
            self.assertIn('sandbox_mode = "workspace-write"', config_text)
            self.assertNotIn("model_instructions_file", config_text)
            self.assertIn("developer_instructions", config_text)
            self.assertIn("BEGIN codex-hardening network guidance", config_text)
            self.assertIn("codex-net autoexec -- ...", config_text)
            self.assertIn("[features]", config_text)
            self.assertIn("codex_hooks = true", config_text)
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
            self.assertIn("Config merge summary:", result.stdout)

    def test_enable_script_runs_install_and_prints_backend_choices(self) -> None:
        with TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            env = dict(os.environ)
            env["HOME"] = str(home)

            result = subprocess.run(
                ["bash", str(ENABLE_SCRIPT)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((home / ".codex" / "scripts" / "codex-net").exists())
            self.assertIn("Choose your backend:", result.stdout)
            self.assertIn(f"{home}/.codex/scripts/codex-net use hook_only", result.stdout)
            self.assertIn(f"{home}/.codex/scripts/codex-net use netns --prepare --sudo", result.stdout)
            self.assertIn("Current chooser:", result.stdout)
            self.assertIn("backend_choices:", result.stdout)

    def test_install_script_preserves_existing_developer_instructions(self) -> None:
        with TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            codex_dir = home / ".codex"
            (codex_dir / "hooks").mkdir(parents=True)
            (codex_dir / "policies").mkdir(parents=True)

            (codex_dir / "config.toml").write_text('developer_instructions = "Keep this custom guidance."\n')
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
            config_text = (codex_dir / "config.toml").read_text()
            self.assertIn("Keep this custom guidance.", config_text)
            self.assertIn("BEGIN codex-hardening network guidance", config_text)
            self.assertIn("developer_instructions: appended", result.stdout)


if __name__ == "__main__":
    unittest.main()
