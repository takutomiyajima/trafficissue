import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import run_analysis


class RunAnalysisProxyTest(unittest.TestCase):
    @patch("run_analysis.adb_shell")
    @patch("run_analysis.adb")
    def test_setup_proxy_prefers_adb_reverse_and_preserves_previous_proxy(self, mock_adb, mock_adb_shell):
        def adb_shell_side_effect(command, serial=None, check=True):
            if command == ["settings", "get", "global", "http_proxy"]:
                return run_analysis.subprocess.CompletedProcess(["adb"], 0, stdout="old.proxy:8888\n", stderr="")
            return run_analysis.subprocess.CompletedProcess(["adb"], 0, stdout="", stderr="")

        mock_adb_shell.side_effect = adb_shell_side_effect
        mock_adb.return_value = run_analysis.subprocess.CompletedProcess(["adb"], 0, stdout="", stderr="")

        state = run_analysis.setup_device_proxy(8080, serial="device-1")

        self.assertEqual(state.host, "127.0.0.1")
        self.assertEqual(state.port, 8080)
        self.assertEqual(state.previous_http_proxy, "old.proxy:8888")
        self.assertTrue(state.reverse_configured)
        mock_adb.assert_called_once_with(["reverse", "tcp:8080", "tcp:8080"], serial="device-1", check=False)
        mock_adb_shell.assert_any_call(["settings", "put", "global", "http_proxy", "127.0.0.1:8080"], serial="device-1")
        mock_adb_shell.assert_any_call(["settings", "put", "global", "global_http_proxy_host", "127.0.0.1"], serial="device-1", check=False)
        mock_adb_shell.assert_any_call(["settings", "put", "global", "global_http_proxy_port", "8080"], serial="device-1", check=False)

    @patch("run_analysis.adb_shell")
    @patch("run_analysis.adb")
    def test_setup_proxy_uses_emulator_gateway_without_reverse(self, mock_adb, mock_adb_shell):
        def adb_shell_side_effect(command, serial=None, check=True):
            if command == ["settings", "get", "global", "http_proxy"]:
                return run_analysis.subprocess.CompletedProcess(["adb"], 0, stdout=":0\n", stderr="")
            if command == ["getprop", "ro.kernel.qemu"]:
                return run_analysis.subprocess.CompletedProcess(["adb"], 0, stdout="1\n", stderr="")
            return run_analysis.subprocess.CompletedProcess(["adb"], 0, stdout="", stderr="")

        mock_adb_shell.side_effect = adb_shell_side_effect

        state = run_analysis.setup_device_proxy(8080, serial="emulator-5554")

        self.assertEqual(state.host, "10.0.2.2")
        self.assertEqual(state.previous_http_proxy, "")
        self.assertFalse(state.reverse_configured)
        mock_adb.assert_not_called()
        mock_adb_shell.assert_any_call(["settings", "put", "global", "http_proxy", "10.0.2.2:8080"], serial="emulator-5554")

    @patch("run_analysis.adb_shell")
    @patch("run_analysis.adb")
    def test_restore_proxy_clears_when_no_previous_proxy_and_removes_reverse(self, mock_adb, mock_adb_shell):
        state = run_analysis.ProxyState(host="127.0.0.1", port=8080, previous_http_proxy="", reverse_configured=True)

        run_analysis.restore_device_proxy(state, serial="device-1")

        mock_adb_shell.assert_any_call(["settings", "put", "global", "http_proxy", ":0"], serial="device-1", check=False)
        mock_adb_shell.assert_any_call(["settings", "delete", "global", "global_http_proxy_host"], serial="device-1", check=False)
        mock_adb_shell.assert_any_call(["settings", "delete", "global", "global_http_proxy_port"], serial="device-1", check=False)
        mock_adb.assert_called_once_with(["reverse", "--remove", "tcp:8080"], serial="device-1", check=False)

    @patch("run_analysis.time.sleep")
    @patch("run_analysis.subprocess.Popen")
    @patch("run_analysis.shutil.which", return_value="/usr/local/bin/mitmdump")
    def test_start_mitmproxy_uses_absolute_paths_and_initializes_log(self, mock_which, mock_popen, mock_sleep):
        class FakeProcess:
            returncode = None

            def poll(self):
                return None

        mock_popen.return_value = FakeProcess()

        with tempfile.TemporaryDirectory() as tmp:
            previous_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                proc = run_analysis.start_mitmproxy(8080)

                self.assertIs(proc, mock_popen.return_value)
                traffic_path = Path(tmp) / "logs" / "traffic_logs.csv"
                self.assertEqual(
                    traffic_path.read_text(encoding="utf-8"),
                    "timestamp,scheme,domain,method,url,status_code,content_type,request_size,response_size\n",
                )
                command = mock_popen.call_args.args[0]
                self.assertIn(str(Path(tmp) / "capture_traffic.py"), command)
                self.assertIn("block_global=false", command)
                self.assertEqual(mock_popen.call_args.kwargs["env"]["TRAFFIC_LOG_PATH"], str(traffic_path))
            finally:
                os.chdir(previous_cwd)

    def test_warn_if_no_traffic_records_reports_header_only_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            traffic_path = Path(tmp) / "traffic_logs.csv"
            traffic_path.write_text("timestamp,scheme,domain,method,url,status_code,content_type,request_size,response_size\n", encoding="utf-8")

            output = io.StringIO()
            with redirect_stdout(output):
                run_analysis.warn_if_no_traffic_records(str(traffic_path))

            warning = output.getvalue()
            self.assertIn("contains only the header", warning)
            self.assertIn("--proxy-host 10.0.2.2 --no-adb-reverse", warning)


if __name__ == "__main__":
    unittest.main()
