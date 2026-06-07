import tempfile
import unittest
from pathlib import Path

from analyze_logs import analyze, classify_risk, detect_sensitive_url_fields, is_system_connectivity_probe
from risk_rules import destination_party


def has_pandas() -> bool:
    try:
        import pandas  # noqa: F401
    except ModuleNotFoundError:
        return False
    return True


class AnalyzeLogsTest(unittest.TestCase):
    def test_classify_https_allowlist_and_external(self):
        first_party = classify_risk("https", "api.example.com", "Login")
        external = classify_risk("https", "unknown-site.com", "Open Page")

        self.assertEqual(first_party.severity, "Low")
        self.assertEqual(first_party.category, "First-party HTTPS")
        self.assertEqual(first_party.rule_id, "first_party_https")
        self.assertEqual(external.severity, "Medium")
        self.assertEqual(external.category, "第三者ドメイン通信")
        self.assertEqual(external.rule_id, "third_party_domain")

    def test_classify_core_mvp_risks(self):
        plain_http = classify_risk("http", "plain.example.net", "Open")
        tracker = classify_risk("https", "stats.doubleclick.net", "Open")
        startup = classify_risk("https", "api.example.com", "Start", time_delta=1.5, event_id="E001")
        unreadable = classify_risk("", "", "Open")

        self.assertEqual(plain_http.severity, "High")
        self.assertEqual(plain_http.category, "HTTP平文通信")
        self.assertEqual(plain_http.rule_id, "cleartext_http")
        self.assertEqual(tracker.severity, "Medium")
        self.assertEqual(tracker.category, "広告・解析系通信")
        self.assertEqual(tracker.rule_id, "tracker_domain")
        self.assertEqual(startup.severity, "Medium")
        self.assertEqual(startup.category, "起動直後通信")
        self.assertEqual(startup.rule_id, "startup_transmission")
        self.assertEqual(unreadable.severity, "Unknown")
        self.assertEqual(unreadable.category, "判定不能通信")
        self.assertEqual(unreadable.rule_id, "unreadable_traffic")

    def test_detects_sensitive_url_fields_without_exposing_values(self):
        labels = detect_sensitive_url_fields(
            "https://api.example.com/v1/profile?email=user%40example.com&android_id=abc123&lat=35.0"
        )
        self.assertIn("email", labels)
        self.assertIn("device_id", labels)
        self.assertIn("location", labels)

        decision = classify_risk(
            "https",
            "api.example.com",
            "Profile",
            url="https://api.example.com/v1/profile?email=user%40example.com&android_id=abc123",
        )
        self.assertEqual(decision.severity, "High")
        self.assertEqual(decision.category, "個人情報らしいキー")
        self.assertEqual(decision.rule_id, "sensitive_key")
        self.assertIn("email", decision.data_categories)
        self.assertNotIn("user@example.com", decision.reason)

    def test_destination_party_classifies_allowlisted_domains(self):
        self.assertEqual(destination_party("api.example.com", ("example.com",)), "first-party")
        self.assertEqual(destination_party("tracker.example.net", ("example.com",)), "third-party")
        self.assertEqual(destination_party("", ("example.com",)), "unknown")

    def test_identifies_android_connectivity_probe_noise(self):
        self.assertTrue(
            is_system_connectivity_probe(
                "http",
                "connectivitycheck.gstatic.com",
                "http://connectivitycheck.gstatic.com/generate_204",
                204,
            )
        )
        self.assertTrue(
            is_system_connectivity_probe(
                "http",
                "www.google.com",
                "http://www.google.com/gen_204",
                "204",
            )
        )
        self.assertFalse(
            is_system_connectivity_probe(
                "https",
                "example.com",
                "https://example.com/",
                200,
            )
        )

    @unittest.skipIf(not has_pandas(), "pandas is not installed in this environment")
    def test_analyze_adds_mvp_fields_and_rule_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ui_path = base / "ui_events.csv"
            traffic_path = base / "traffic_logs.csv"
            output_path = base / "risk_results.csv"

            ui_path.write_text(
                "event_id,timestamp,screen,action,element_text\n"
                "E001,100.0,com.example/.MainActivity,tap,Open Page\n"
                "E002,200.0,com.example/.MainActivity,tap,Help\n",
                encoding="utf-8",
            )
            traffic_path.write_text(
                "timestamp,scheme,domain,method,url,status_code,content_type,request_size,response_size\n"
                "100.75,https,unknown-site.com,GET,https://unknown-site.com,200,text/html,0,20\n"
                "101.25,https,api.example.com,GET,https://api.example.com/profile?phone=09012345678,200,application/json,0,42\n"
                "210.0,http,in-window-too-late.test,GET,http://in-window-too-late.test,200,text/plain,0,12\n",
                encoding="utf-8",
            )

            df = analyze(str(ui_path), str(traffic_path), str(output_path), window_seconds=5)

            first = df[df["domain"] == "unknown-site.com"].iloc[0]
            self.assertEqual(first["app_package"], "com.example")
            self.assertEqual(first["observability_status"], "observed")
            self.assertEqual(first["time_delta"], 0.75)
            self.assertEqual(first["risk"], "Medium")
            self.assertEqual(first["risk_rule"], "startup_transmission")
            self.assertEqual(first["destination_party"], "third-party")
            self.assertEqual(first["content_type"], "text/html")
            self.assertEqual(str(first["response_size"]), "20")

            sensitive = df[df["risk_rule"] == "sensitive_key"].iloc[0]
            self.assertEqual(sensitive["event_id"], "E001")
            self.assertEqual(sensitive["risk"], "High")
            self.assertEqual(sensitive["risk_category"], "個人情報らしいキー")
            self.assertEqual(sensitive["data_categories"], "phone")
            self.assertEqual(sensitive["destination_party"], "first-party")
            self.assertNotIn("09012345678", sensitive["reason"])

            second = df[df["event_id"] == "E002"].iloc[0]
            self.assertEqual(second["observability_status"], "none")
            self.assertEqual(second["risk"], "Low")
            self.assertEqual(second["risk_rule"], "no_traffic")
            self.assertIn("5秒以内", second["reason"])

    @unittest.skipIf(not has_pandas(), "pandas is not installed in this environment")
    def test_analyze_derives_http_scheme_from_url_before_classifying(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ui_path = base / "ui_events.csv"
            traffic_path = base / "traffic_logs.csv"
            output_path = base / "risk_results.csv"

            ui_path.write_text(
                "event_id,timestamp,screen,action,element_text\n"
                "E002,100.0,com.example/.MainActivity,tap,Open Page\n",
                encoding="utf-8",
            )
            traffic_path.write_text(
                "timestamp,scheme,domain,method,url,status_code\n"
                "101,,,GET,http://plain.example.net/path,200\n",
                encoding="utf-8",
            )

            df = analyze(str(ui_path), str(traffic_path), str(output_path), window_seconds=5)

            first = df.iloc[0]
            self.assertEqual(first["observability_status"], "observed")
            self.assertEqual(first["scheme"], "http")
            self.assertEqual(first["domain"], "plain.example.net")
            self.assertEqual(first["risk"], "High")
            self.assertEqual(first["risk_rule"], "cleartext_http")

    @unittest.skipIf(not has_pandas(), "pandas is not installed in this environment")
    def test_analyze_marks_unreadable_traffic_with_separate_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ui_path = base / "ui_events.csv"
            traffic_path = base / "traffic_logs.csv"
            output_path = base / "risk_results.csv"

            ui_path.write_text(
                "event_id,timestamp,screen,action,element_text\n"
                "E002,100.0,com.example/.MainActivity,tap,Open Page\n",
                encoding="utf-8",
            )
            traffic_path.write_text(
                "timestamp,scheme,domain,method,url,status_code\n"
                "101,,,GET,,0\n",
                encoding="utf-8",
            )

            df = analyze(str(ui_path), str(traffic_path), str(output_path), window_seconds=5)

            first = df.iloc[0]
            self.assertEqual(first["observability_status"], "unreadable")
            self.assertEqual(first["risk"], "Unknown")
            self.assertEqual(first["risk_rule"], "unreadable_traffic")
            self.assertEqual(first["risk_category"], "判定不能通信")

    @unittest.skipIf(not has_pandas(), "pandas is not installed in this environment")
    def test_analyze_filters_connectivity_probes_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ui_path = base / "ui_events.csv"
            traffic_path = base / "traffic_logs.csv"
            output_path = base / "risk_results.csv"

            ui_path.write_text(
                "event_id,timestamp,screen,action,element_text\n"
                "E001,100.0,Home,tap,First-party HTTPS Test\n",
                encoding="utf-8",
            )
            traffic_path.write_text(
                "timestamp,scheme,domain,method,url,status_code\n"
                "101,http,connectivitycheck.gstatic.com,GET,http://connectivitycheck.gstatic.com/generate_204,204\n"
                "101,http,connectivitycheck.gstatic.com,GET,http://connectivitycheck.gstatic.com/generate_204,204\n"
                "102,http,play.googleapis.com,GET,http://play.googleapis.com/generate_204,204\n"
                "103,https,example.com,GET,https://example.com/,200\n",
                encoding="utf-8",
            )

            df = analyze(str(ui_path), str(traffic_path), str(output_path), window_seconds=5)

            self.assertEqual(len(df), 1)
            first = df.iloc[0]
            self.assertEqual(first["domain"], "example.com")
            self.assertEqual(first["risk"], "Medium")
            self.assertEqual(first["risk_rule"], "startup_transmission")

            df_with_probes = analyze(
                str(ui_path),
                str(traffic_path),
                str(output_path),
                window_seconds=5,
                include_system_probes=True,
            )
            self.assertEqual(len(df_with_probes), 3)
            self.assertIn("connectivitycheck.gstatic.com", set(df_with_probes["domain"]))

    @unittest.skipIf(not has_pandas(), "pandas is not installed in this environment")
    def test_analyze_handles_empty_traffic_log_as_no_observed_traffic(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ui_path = base / "ui_events.csv"
            traffic_path = base / "traffic_logs.csv"
            output_path = base / "risk_results.csv"

            ui_path.write_text(
                "event_id,timestamp,screen,action,element_text\n"
                "E001,100.0,Home,tap,No Traffic Test\n",
                encoding="utf-8",
            )
            traffic_path.write_text("", encoding="utf-8")

            df = analyze(str(ui_path), str(traffic_path), str(output_path), window_seconds=5)

            self.assertEqual(len(df), 1)
            first = df.iloc[0]
            self.assertEqual(first["event_id"], "E001")
            self.assertEqual(first["observability_status"], "none")
            self.assertEqual(first["risk"], "Low")


    @unittest.skipIf(not has_pandas(), "pandas is not installed in this environment")
    def test_analyze_handles_header_only_traffic_log_as_no_observed_traffic(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ui_path = base / "ui_events.csv"
            traffic_path = base / "traffic_logs.csv"
            output_path = base / "risk_results.csv"

            ui_path.write_text(
                "event_id,timestamp,screen,action,element_text\n"
                "E001,100.0,com.example/.MainActivity,tap,HTTP Test\n",
                encoding="utf-8",
            )
            traffic_path.write_text(
                "timestamp,scheme,domain,method,url,status_code,content_type,request_size,response_size\n",
                encoding="utf-8",
            )

            df = analyze(str(ui_path), str(traffic_path), str(output_path), window_seconds=5)

            self.assertEqual(len(df), 1)
            first = df.iloc[0]
            self.assertEqual(first["event_id"], "E001")
            self.assertEqual(first["app_package"], "com.example")
            self.assertEqual(first["observability_status"], "none")
            self.assertEqual(first["risk_rule"], "no_traffic")

    @unittest.skipIf(not has_pandas(), "pandas is not installed in this environment")
    def test_analyze_normalizes_log_headers_before_correlation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ui_path = base / "ui_events.csv"
            traffic_path = base / "traffic_logs.csv"
            output_path = base / "risk_results.csv"

            ui_path.write_text(
                " event_id , timestamp , screen , action , element_text \n"
                "E001,100.0,Home,tap,Open Page\n",
                encoding="utf-8",
            )
            traffic_path.write_text(
                "\ufeff timestamp , scheme , domain , method , url , status_code \n"
                "101,https,unknown-site.com,GET,https://unknown-site.com,200\n",
                encoding="utf-8",
            )

            df = analyze(str(ui_path), str(traffic_path), str(output_path), window_seconds=5)

            first = df.iloc[0]
            self.assertEqual(first["event_id"], "E001")
            self.assertEqual(first["domain"], "unknown-site.com")
            self.assertEqual(first["observability_status"], "observed")


if __name__ == "__main__":
    unittest.main()
