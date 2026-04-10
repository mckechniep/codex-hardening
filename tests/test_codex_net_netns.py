import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import codex_net_netns
from codex_net_netns import BackendError, namespace_launch_command, netns_doctor_report, run_netns_spike


class NetnsDoctorReportTests(unittest.TestCase):
    @mock.patch.object(codex_net_netns, "detect_environment")
    @mock.patch.object(codex_net_netns, "_kernel_config_value")
    @mock.patch.object(codex_net_netns, "shutil")
    def test_netns_doctor_report_accepts_ready_host(
        self,
        mock_shutil: mock.Mock,
        mock_kernel_config_value: mock.Mock,
        mock_detect_environment: mock.Mock,
    ) -> None:
        mock_detect_environment.return_value = {
            "platform": "linux",
            "osrelease": "6.6.87.2-microsoft-standard-WSL2",
            "version": "Linux version",
            "is_linux": "true",
            "is_wsl": "true",
            "is_wsl2": "true",
        }
        mock_shutil.which.side_effect = lambda name: f"/usr/bin/{name}"
        mock_kernel_config_value.side_effect = lambda symbol: {"CONFIG_NET_NS": "y", "CONFIG_VETH": "y", "CONFIG_NF_NAT": "y"}[symbol]

        report = netns_doctor_report()
        self.assertTrue(report["ready"])
        self.assertTrue(any(item["name"] == "net_ns" and item["ok"] == "true" for item in report["checks"]))

    @mock.patch.object(codex_net_netns, "detect_environment")
    @mock.patch.object(codex_net_netns, "_kernel_config_value")
    @mock.patch.object(codex_net_netns, "shutil")
    def test_netns_doctor_report_flags_missing_veth(
        self,
        mock_shutil: mock.Mock,
        mock_kernel_config_value: mock.Mock,
        mock_detect_environment: mock.Mock,
    ) -> None:
        mock_detect_environment.return_value = {
            "platform": "linux",
            "osrelease": "6.6.87.2-microsoft-standard-WSL2",
            "version": "Linux version",
            "is_linux": "true",
            "is_wsl": "true",
            "is_wsl2": "true",
        }
        mock_shutil.which.side_effect = lambda name: f"/usr/bin/{name}"
        mock_kernel_config_value.side_effect = lambda symbol: {"CONFIG_NET_NS": "y", "CONFIG_VETH": "n", "CONFIG_NF_NAT": "y"}[symbol]

        report = netns_doctor_report()
        self.assertFalse(report["ready"])
        self.assertTrue(any(item["name"] == "veth" and item["ok"] == "false" for item in report["checks"]))


class NamespaceLaunchCommandTests(unittest.TestCase):
    def test_namespace_launch_command_drops_to_calling_user(self) -> None:
        command = namespace_launch_command("codex-net-abcd1234", 1000, 1000, ["python3", "-V"])
        self.assertEqual(
            command[:11],
            [
                "ip",
                "netns",
                "exec",
                "codex-net-abcd1234",
                "setpriv",
                "--reuid",
                "1000",
                "--regid",
                "1000",
                "--init-groups",
                "--",
            ],
        )


class NetnsSpikeLifecycleTests(unittest.TestCase):
    @mock.patch.object(codex_net_netns, "netns_doctor_report", return_value={"ready": False, "checks": [{"name": "ip", "required": "true", "ok": "false"}]})
    def test_run_netns_spike_fails_when_host_is_not_ready(self, mock_doctor: mock.Mock) -> None:
        with self.assertRaisesRegex(BackendError, "Missing prerequisites"):
            run_netns_spike(["python3", "-V"], use_sudo=True)

    @mock.patch.object(codex_net_netns, "os")
    def test_run_netns_spike_requires_sudo_when_not_root(self, mock_os: mock.Mock) -> None:
        mock_os.geteuid.return_value = 1000
        with self.assertRaisesRegex(BackendError, "--sudo"):
            run_netns_spike(["python3", "-V"], use_sudo=False)

    @mock.patch.object(codex_net_netns, "_namespace_token", return_value="abcd1234")
    @mock.patch.object(codex_net_netns, "netns_doctor_report", return_value={"ready": True, "checks": []})
    @mock.patch.object(codex_net_netns, "subprocess")
    @mock.patch.object(codex_net_netns, "os")
    def test_run_netns_spike_creates_namespace_and_cleans_up(
        self,
        mock_os: mock.Mock,
        mock_subprocess: mock.Mock,
        mock_doctor: mock.Mock,
        mock_token: mock.Mock,
    ) -> None:
        mock_os.geteuid.return_value = 1000
        mock_os.getuid.return_value = 1000
        mock_os.getgid.return_value = 1000
        mock_os.getcwd.return_value = str(ROOT)
        mock_os.environ = {"PATH": "/usr/bin", "HOME": "/home/test"}

        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        command_result = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        mock_subprocess.run.side_effect = [
            success,
            success,
            success,
            success,
            success,
            success,
            success,
            success,
            success,
            command_result,
            success,
            success,
        ]

        details = run_netns_spike(["python3", "-V"], use_sudo=True)

        self.assertEqual(details["namespace"], "codex-net-abcd1234")
        self.assertEqual(details["returncode"], 0)
        first_call = mock_subprocess.run.call_args_list[0].args[0]
        self.assertEqual(first_call[:5], ["sudo", "ip", "netns", "add", "codex-net-abcd1234"])
        launch_call = mock_subprocess.run.call_args_list[9].args[0]
        self.assertEqual(launch_call[:5], ["sudo", "ip", "netns", "exec", "codex-net-abcd1234"])
        cleanup_call = mock_subprocess.run.call_args_list[10].args[0]
        self.assertEqual(cleanup_call[:5], ["sudo", "ip", "link", "del", "cnhabcd1234"])


if __name__ == "__main__":
    unittest.main()
