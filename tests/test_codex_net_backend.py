import argparse
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import codex_net_backend


def sample_config() -> dict:
    return {
        "backend": "linux_wsl_netns",
        "default_profile": "offline",
        "profiles": {
            "offline": {"description": "", "allow_localhost": True, "allowed_domains": [], "allowed_tcp_ports": [], "allowed_udp_ports": [], "require_approval": False},
            "registries": {"description": "", "allow_localhost": True, "allowed_domains": ["github.com"], "allowed_tcp_ports": [443], "allowed_udp_ports": [], "require_approval": False},
        },
    }


class CodexNetBackendExecTests(unittest.TestCase):
    @mock.patch.object(codex_net_backend, "run_netns_exec", return_value=23)
    @mock.patch.object(codex_net_backend, "validate_command_for_profile")
    @mock.patch.object(codex_net_backend, "load_config", return_value=sample_config())
    def test_cmd_exec_dispatches_to_netns_backend(
        self,
        mock_load_config: mock.Mock,
        mock_validate: mock.Mock,
        mock_run_netns_exec: mock.Mock,
    ) -> None:
        args = argparse.Namespace(profile="registries", wrapped_command=["--", "npm", "ci"])

        result = codex_net_backend.cmd_exec(args)

        self.assertEqual(result, 23)
        mock_validate.assert_called_once_with(
            "npm ci",
            "registries",
            sample_config(),
            enforce_require_approval=True,
        )
        mock_run_netns_exec.assert_called_once_with("registries", ["npm", "ci"], sample_config())


if __name__ == "__main__":
    unittest.main()
