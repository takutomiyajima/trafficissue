import unittest
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
    def test_auto_explore_finishes_when_current_screen_has_no_new_clickables(self):
        device = FakeDevice()
        with patch("auto_runner.time.sleep"), patch("auto_runner.log_launch_event", return_value=100), patch("auto_runner.log_event", return_value=123):
            auto_runner.auto_explore(device, "com.example", "unused.csv", max_events=10, wait_seconds=1)

        self.assertEqual(device.clicked, [(50, 50)])
        self.assertEqual(device.pressed, [])

    def test_auto_explore_skips_external_package_before_logging_tap(self):
        device = FakeDevice()
        device.current = {"package": "com.android.settings", "activity": ".Settings"}
        with patch("auto_runner.time.sleep"), patch("auto_runner.log_launch_event", return_value=100), patch("auto_runner.log_event", return_value=123) as mock_log:
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
