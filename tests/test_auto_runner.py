import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import auto_runner


class FakeDevice:
    def __init__(self):
        self.clicked = []
        self.pressed = []
        self.current = {"package": "com.example", "activity": ".MainActivity"}
        self.hierarchies = [
            '''<hierarchy><node clickable="true" text="Start" resource-id="btn" class="android.widget.Button" bounds="[0,0][100,100]" /></hierarchy>''',
            '''<hierarchy><node clickable="true" text="Start" resource-id="btn" class="android.widget.Button" bounds="[0,0][100,100]" /></hierarchy>''',
        ]

    def app_start(self, package_name):
        self.started_package = package_name

    def app_current(self):
        return self.current

    def dump_hierarchy(self, compressed=False):
        return self.hierarchies.pop(0)

    def click(self, x, y):
        self.clicked.append((x, y))

    def press(self, key):
        self.pressed.append(key)


class AutoRunnerTest(unittest.TestCase):
    def test_find_android_tool_uses_standard_macos_sdk_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = Path(tmp) / "Library" / "Android" / "sdk" / "build-tools" / "35.0.0" / "aapt"
            tool.parent.mkdir(parents=True)
            tool.write_text("#!/bin/sh\n", encoding="utf-8")
            tool.chmod(0o755)

            with patch("auto_runner.shutil.which", return_value=None), patch(
                "auto_runner.Path.home", return_value=Path(tmp)
            ), patch.dict(os.environ, {"ANDROID_HOME": "", "ANDROID_SDK_ROOT": ""}):
                self.assertEqual(auto_runner.find_android_tool("aapt"), str(tool))

    @patch("auto_runner.run_command")
    @patch("auto_runner.find_android_tool", return_value="/sdk/build-tools/35.0.0/aapt")
    def test_extract_package_uses_discovered_absolute_tool_path(self, mock_find, mock_run):
        mock_run.return_value = auto_runner.subprocess.CompletedProcess(
            ["aapt"], 0, stdout="package: name='com.example.app' versionCode='1'\n", stderr=""
        )

        self.assertEqual(auto_runner.extract_package_with_android_tools("app.apk"), "com.example.app")
        mock_run.assert_called_once_with(
            ["/sdk/build-tools/35.0.0/aapt", "dump", "badging", "app.apk"], check=False
        )

    def test_wait_until_foreground_waits_past_launcher(self):
        device = FakeDevice()
        states = iter(
            [
                {"package": "com.google.android.apps.nexuslauncher"},
                {"package": "com.example"},
            ]
        )
        device.app_current = lambda: next(states)
        with patch("auto_runner.time.sleep"):
            self.assertTrue(
                auto_runner.wait_until_foreground(
                    device,
                    "com.example",
                    timeout_seconds=1,
                )
            )

    def test_auto_explore_finishes_when_current_screen_has_no_new_clickables(self):
        device = FakeDevice()
        with patch("auto_runner.time.sleep"), patch("auto_runner.log_launch_event", return_value=100), patch("auto_runner.log_event", return_value=123):
            auto_runner.auto_explore(device, "com.example", "unused.csv", max_events=10, wait_seconds=1)

        self.assertEqual(device.clicked, [(50, 50)])
        self.assertEqual(device.pressed, [])

    def test_auto_explore_skips_external_package_before_logging_tap(self):
        device = FakeDevice()
        device.current = {"package": "com.android.settings", "activity": ".Settings"}
        with patch("auto_runner.time.sleep"), patch("auto_runner.wait_until_foreground", return_value=False), patch("auto_runner.log_launch_event", return_value=100), patch("auto_runner.log_event", return_value=123) as mock_log:
            def restore_target(key):
                device.pressed.append(key)
                device.current = {"package": "com.example", "activity": ".MainActivity"}

            device.press = restore_target
            auto_runner.auto_explore(device, "com.example", "unused.csv", max_events=1, wait_seconds=1)

        self.assertEqual(device.pressed, ["back"])
        self.assertEqual(device.clicked, [(50, 50)])
        self.assertEqual(mock_log.call_count, 1)

if __name__ == "__main__":
    unittest.main()
