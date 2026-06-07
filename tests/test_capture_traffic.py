import importlib
import sys
import tempfile
import types
import unittest
from pathlib import Path


class CaptureTrafficTest(unittest.TestCase):
    def test_response_writes_status_code_to_csv_immediately(self):
        fake_mitmproxy = types.ModuleType("mitmproxy")
        fake_http = types.ModuleType("mitmproxy.http")
        fake_http.HTTPFlow = object
        fake_mitmproxy.http = fake_http

        original_mitmproxy = sys.modules.get("mitmproxy")
        original_http = sys.modules.get("mitmproxy.http")
        sys.modules["mitmproxy"] = fake_mitmproxy
        sys.modules["mitmproxy.http"] = fake_http
        try:
            import capture_traffic

            capture_traffic = importlib.reload(capture_traffic)
            with tempfile.TemporaryDirectory() as tmp:
                csv_path = Path(tmp) / "traffic_logs.csv"
                logger = capture_traffic.TrafficLogger(str(csv_path))
                flow = types.SimpleNamespace(
                    request=types.SimpleNamespace(
                        scheme="https",
                        host="api.example.com",
                        method="GET",
                        url="https://api.example.com/v1/status",
                    ),
                    response=types.SimpleNamespace(status_code=200),
                )

                logger.response(flow)

                self.assertIn("status_code", csv_path.read_text(encoding="utf-8"))
                self.assertIn(",200\n", csv_path.read_text(encoding="utf-8"))
        finally:
            if original_mitmproxy is None:
                sys.modules.pop("mitmproxy", None)
            else:
                sys.modules["mitmproxy"] = original_mitmproxy
            if original_http is None:
                sys.modules.pop("mitmproxy.http", None)
            else:
                sys.modules["mitmproxy.http"] = original_http


if __name__ == "__main__":
    unittest.main()
