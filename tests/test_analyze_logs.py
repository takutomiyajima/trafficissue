import tempfile
import unittest
from pathlib import Path

from analyze_logs import analyze, classify_risk


def has_pandas() -> bool:
    try:
        import pandas  # noqa: F401
    except ModuleNotFoundError:
        return False
    return True


class AnalyzeLogsTest(unittest.TestCase):
    def test_classify_https_allowlist_and_external(self):
        self.assertEqual(classify_risk("https", "api.example.com", "Login").risk, "Low")
        self.assertEqual(classify_risk("https", "unknown-site.com", "Open Page").risk, "Middle")

    def test_classify_high_risks(self):
        self.assertEqual(classify_risk("http", "plain.example.net", "Open").risk, "High")
        self.assertEqual(classify_risk("https", "maps.googleapis.com", "Location").risk, "High")
        self.assertEqual(classify_risk("https", "stats.doubleclick.net", "Open").risk, "High")

    @unittest.skipIf(not has_pandas(), "pandas is not installed in this environment")
    def test_analyze_adds_time_delta_reason_and_observability(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ui_path = base / "ui_events.csv"
            traffic_path = base / "traffic_logs.csv"
            output_path = base / "risk_results.csv"

            ui_path.write_text(
                "event_id,timestamp,screen,action,element_text\n"
                "E001,100.0,Home,tap,Open Page\n"
                "E002,200.0,Home,tap,Help\n",
                encoding="utf-8",
            )
            traffic_path.write_text(
                "timestamp,scheme,domain,method,url,status_code\n"
                "100.75,https,unknown-site.com,GET,https://unknown-site.com,200\n"
                "210.0,http,in-window-too-late.test,GET,http://in-window-too-late.test,200\n",
                encoding="utf-8",
            )

            df = analyze(str(ui_path), str(traffic_path), str(output_path), window_seconds=5)

            first = df[df["event_id"] == "E001"].iloc[0]
            self.assertEqual(first["observability_status"], "observed")
            self.assertEqual(first["time_delta"], 0.75)
            self.assertEqual(first["risk"], "Middle")
            self.assertIn("allowlist外", first["reason"])

            second = df[df["event_id"] == "E002"].iloc[0]
            self.assertEqual(second["observability_status"], "none")
            self.assertEqual(second["risk"], "Low")
            self.assertIn("5秒以内", second["reason"])


if __name__ == "__main__":
    unittest.main()
