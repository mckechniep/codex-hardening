import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import codex_net_netns
from codex_net_netns import (
    BackendError,
    apply_netns_base,
    exec_table_name,
    namespace_launch_command,
    netns_backend_status_report,
    netns_base_rules_path,
    netns_doctor_report,
    render_exec_rules,
    run_netns_exec,
    run_netns_spike,
)
from codex_net_wsl import write_backend_state


def sample_config() -> dict:
    return {
        "backend": "linux_wsl_netns",
        "backend_linux_wsl_netns": {
            "namespace_prefix": "codex-net",
            "host_veth_prefix": "cnh",
            "guest_veth_prefix": "cng",
            "nft_table_name": "codex_netns_runtime",
        },
        "profiles": {
            "offline": {
                "description": "No remote network access.",
                "allow_localhost": True,
                "allowed_domains": [],
                "allowed_tcp_ports": [],
                "allowed_udp_ports": [],
                "require_approval": False,
            },
            "registries": {
                "description": "Common package registries and source hosts.",
                "allow_localhost": True,
                "allowed_domains": ["github.com"],
                "allowed_tcp_ports": [443],
                "allowed_udp_ports": [],
                "require_approval": True,
            },
            "dev_local": {
                "description": "Loopback and common local development ports.",
                "allow_localhost": True,
                "allowed_domains": ["localhost", "127.0.0.1"],
                "allowed_tcp_ports": [3000, 8080],
                "allowed_udp_ports": [],
                "require_approval": False,
            },
        },
    }


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

    def test_namespace_launch_command_appends_explicit_environment(self) -> None:
        command = namespace_launch_command(
            "codex-net-abcd1234",
            1000,
            1000,
            ["python3", "-V"],
            extra_env={"CODEX_NET_PROFILE": "registries"},
        )
        self.assertIn("env", command)
        self.assertIn("CODEX_NET_PROFILE=registries", command)


class NetnsSpikeLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.original_state_path = codex_net_netns.os.environ.get("CODEX_NET_STATE_PATH")
        codex_net_netns.os.environ["CODEX_NET_STATE_PATH"] = str(Path(self.tempdir.name) / "backend_state.json")

    def tearDown(self) -> None:
        if self.original_state_path is None:
            codex_net_netns.os.environ.pop("CODEX_NET_STATE_PATH", None)
        else:
            codex_net_netns.os.environ["CODEX_NET_STATE_PATH"] = self.original_state_path

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


class NetnsBackendStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.original_state_path = codex_net_netns.os.environ.get("CODEX_NET_STATE_PATH")
        codex_net_netns.os.environ["CODEX_NET_STATE_PATH"] = str(Path(self.tempdir.name) / "backend_state.json")

    def tearDown(self) -> None:
        if self.original_state_path is None:
            codex_net_netns.os.environ.pop("CODEX_NET_STATE_PATH", None)
        else:
            codex_net_netns.os.environ["CODEX_NET_STATE_PATH"] = self.original_state_path

    @mock.patch.object(codex_net_netns, "subprocess")
    @mock.patch.object(codex_net_netns, "netns_doctor_report", return_value={"ready": True, "checks": []})
    def test_apply_netns_base_writes_rules_and_returns_details(
        self,
        mock_doctor: mock.Mock,
        mock_subprocess: mock.Mock,
    ) -> None:
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        missing = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="No such file or directory")
        mock_subprocess.run.side_effect = [success, missing, success]

        details = apply_netns_base(sample_config(), use_sudo=True)

        self.assertEqual(details["table_name"], "codex_netns_runtime")
        self.assertTrue(Path(details["base_nft_path"]).exists())
        rendered = netns_base_rules_path().read_text()
        self.assertIn("table inet codex_netns_runtime", rendered)
        self.assertIn("chain codex_netns_postrouting", rendered)

    def test_netns_backend_status_report_accepts_matching_state(self) -> None:
        base_path = netns_base_rules_path()
        base_path.parent.mkdir(parents=True, exist_ok=True)
        base_path.write_text("table inet codex_netns_runtime {}\n")
        write_backend_state(
            {
                "json_path": None,
                "nft_path": None,
                "nft_sha256": None,
                "manifest": {"backend": "linux_wsl_netns"},
            },
            applied=True,
            extra={
                "base_nft_path": str(base_path),
                "base_nft_sha256": codex_net_netns.sha256(base_path.read_bytes()).hexdigest(),
                "table_name": "codex_netns_runtime",
            },
        )

        report = netns_backend_status_report(sample_config())
        self.assertTrue(report["ready"])
        self.assertEqual(report["active_exec_count"], 0)

    def test_netns_backend_status_report_flags_missing_base_rules(self) -> None:
        missing_path = netns_base_rules_path()
        write_backend_state(
            {
                "json_path": None,
                "nft_path": None,
                "nft_sha256": None,
                "manifest": {"backend": "linux_wsl_netns"},
            },
            applied=True,
            extra={
                "base_nft_path": str(missing_path),
                "base_nft_sha256": "deadbeef",
                "table_name": "codex_netns_runtime",
            },
        )

        report = netns_backend_status_report(sample_config())
        self.assertFalse(report["ready"])
        self.assertTrue(any("base nftables file is missing" in issue for issue in report["issues"]))


class NetnsExecRulesTests(unittest.TestCase):
    def test_render_exec_rules_contains_profile_specific_allowlist(self) -> None:
        rendered = render_exec_rules(
            sample_config(),
            "abcd1234",
            "cnhabcd1234",
            {
                "subnet": "169.254.10.0/30",
                "host_ip": "169.254.10.1",
                "guest_ip": "169.254.10.2",
                "host_cidr": "169.254.10.1/30",
                "guest_cidr": "169.254.10.2/30",
            },
            sample_config()["profiles"]["registries"],
            {"github.com": ["140.82.112.3"]},
        )

        self.assertIn(f"table inet {exec_table_name(sample_config(), 'abcd1234')}", rendered)
        self.assertIn('iifname "cnhabcd1234" ip daddr { 140.82.112.3 } tcp dport { 443 } accept', rendered)
        self.assertIn('iifname "cnhabcd1234" reject with icmpx admin-prohibited', rendered)


class NetnsExecLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.original_state_path = codex_net_netns.os.environ.get("CODEX_NET_STATE_PATH")
        codex_net_netns.os.environ["CODEX_NET_STATE_PATH"] = str(Path(self.tempdir.name) / "backend_state.json")

    def tearDown(self) -> None:
        if self.original_state_path is None:
            codex_net_netns.os.environ.pop("CODEX_NET_STATE_PATH", None)
        else:
            codex_net_netns.os.environ["CODEX_NET_STATE_PATH"] = self.original_state_path

    @mock.patch.object(codex_net_netns, "netns_backend_status_report", return_value={"ready": False, "issues": ["No backend state file has been recorded yet."]})
    def test_run_netns_exec_requires_ready_backend_state(self, mock_status: mock.Mock) -> None:
        with self.assertRaisesRegex(BackendError, "not ready"):
            run_netns_exec("registries", ["curl", "https://github.com"], sample_config(), use_sudo=True)

    @mock.patch.object(codex_net_netns, "netns_doctor_report", return_value={"ready": True, "checks": []})
    @mock.patch.object(codex_net_netns, "netns_backend_status_report", return_value={"ready": True, "issues": []})
    def test_run_netns_exec_rejects_localhost_targets(
        self,
        mock_status: mock.Mock,
        mock_doctor: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(BackendError, "namespace-local"):
            run_netns_exec("dev_local", ["curl", "http://localhost:3000"], sample_config(), use_sudo=True)

    @mock.patch.object(codex_net_netns, "_resolve_domain_ipv4", return_value=["140.82.112.3"])
    @mock.patch.object(codex_net_netns, "_namespace_token", return_value="abcd1234")
    @mock.patch.object(codex_net_netns, "netns_doctor_report", return_value={"ready": True, "checks": []})
    @mock.patch.object(codex_net_netns, "netns_backend_status_report", return_value={"ready": True, "issues": []})
    @mock.patch.object(codex_net_netns, "subprocess")
    @mock.patch.object(codex_net_netns, "os")
    def test_run_netns_exec_applies_runtime_rules_and_cleans_up(
        self,
        mock_os: mock.Mock,
        mock_subprocess: mock.Mock,
        mock_status: mock.Mock,
        mock_doctor: mock.Mock,
        mock_token: mock.Mock,
        mock_resolve: mock.Mock,
    ) -> None:
        mock_os.geteuid.return_value = 1000
        mock_os.getuid.return_value = 1000
        mock_os.getgid.return_value = 1000
        mock_os.getcwd.return_value = str(ROOT)
        mock_os.environ = {"PATH": "/usr/bin", "HOME": "/home/test"}

        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        command_result = subprocess.CompletedProcess(args=[], returncode=7, stdout="", stderr="")
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
            success,
            success,
            success,
            success,
            success,
            command_result,
            success,
            success,
            success,
            success,
        ]

        result = run_netns_exec("registries", ["curl", "https://github.com"], sample_config(), use_sudo=True)

        self.assertEqual(result, 7)
        launch_call = mock_subprocess.run.call_args_list[14].args[0]
        self.assertEqual(launch_call[:5], ["sudo", "ip", "netns", "exec", "codex-net-abcd1234"])
        self.assertIn("CODEX_NET_HOST_GATEWAY=169.254.172.65", launch_call)
        nft_apply_call = mock_subprocess.run.call_args_list[13].args[0]
        self.assertEqual(nft_apply_call[:3], ["sudo", "nft", "-f"])
        nft_cleanup_call = mock_subprocess.run.call_args_list[15].args[0]
        self.assertEqual(nft_cleanup_call[:6], ["sudo", "nft", "delete", "table", "inet", exec_table_name(sample_config(), "abcd1234")])


if __name__ == "__main__":
    unittest.main()
