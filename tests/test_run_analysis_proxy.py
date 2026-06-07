import unittest
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

    @patch("run_analysis.adb_shell")
    @patch("run_analysis.adb")
    def test_restore_proxy_clears_when_no_previous_proxy_and_removes_reverse(self, mock_adb, mock_adb_shell):
        state = run_analysis.ProxyState(host="127.0.0.1", port=8080, previous_http_proxy="", reverse_configured=True)

        run_analysis.restore_device_proxy(state, serial="device-1")

        mock_adb_shell.assert_any_call(["settings", "put", "global", "http_proxy", ":0"], serial="device-1", check=False)
        mock_adb_shell.assert_any_call(["settings", "delete", "global", "global_http_proxy_host"], serial="device-1", check=False)
        mock_adb_shell.assert_any_call(["settings", "delete", "global", "global_http_proxy_port"], serial="device-1", check=False)
        mock_adb.assert_called_once_with(["reverse", "--remove", "tcp:8080"], serial="device-1", check=False)


if __name__ == "__main__":
    unittest.main()
