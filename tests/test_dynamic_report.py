import unittest

from integration.dynamic_report import build_integrated_report


class DynamicReportTest(unittest.TestCase):
    def test_classifies_supported_confirmed_potential_and_unverified(self):
        handoff = {
            "package_name": "com.example.app",
            "expected_domains": [
                {"domain": "api.example.com", "static_evidence": ["embedded_url_candidate"]},
                {"domain": "unused.example.net", "static_evidence": ["hardcoded_domain"]},
            ],
        }
        rows = [
            {
                "event_id": "E001",
                "observability_status": "observed",
                "metadata_source": "mitmproxy",
                "domain": "api.example.com",
                "scheme": "https",
                "method": "POST",
                "risk": "Medium",
                "risk_category": "外部送信",
                "risk_rule": "third_party_upload",
            },
            {
                "event_id": "E002",
                "observability_status": "observed",
                "metadata_source": "mitmproxy",
                "domain": "runtime-only.example.org",
                "scheme": "https",
                "method": "GET",
                "risk": "Medium",
                "risk_category": "第三者ドメイン通信",
                "risk_rule": "third_party_domain",
            },
            {
                "event_id": "E003",
                "observability_status": "capture_failed",
                "domain": "",
                "risk": "Unknown",
                "risk_category": "観測不能",
                "risk_rule": "no_observed_traffic",
            },
        ]

        report = build_integrated_report(rows, handoff)
        findings = report["findings"]
        by_domain = {item["domain"]: item for item in findings if item["domain"]}

        self.assertEqual(by_domain["api.example.com"]["status"], "Supported")
        self.assertEqual(by_domain["api.example.com"]["confidence"], "high")
        self.assertEqual(by_domain["runtime-only.example.org"]["status"], "Confirmed")
        self.assertEqual(by_domain["unused.example.net"]["status"], "Potential")
        self.assertEqual(
            next(item for item in findings if item["event_id"] == "E003")["status"],
            "Unverified",
        )
        self.assertEqual(
            report["summary"]["status_counts"],
            {"Confirmed": 1, "Potential": 1, "Supported": 1, "Unverified": 1},
        )

    def test_metadata_only_support_has_medium_confidence(self):
        report = build_integrated_report(
            [
                {
                    "event_id": "M001",
                    "observability_status": "metadata_only",
                    "metadata_source": "pcapdroid",
                    "domain": "api.example.com",
                    "risk": "Low",
                    "risk_category": "通信メタデータのみ",
                    "risk_rule": "metadata_only",
                }
            ],
            {
                "expected_domains": [
                    {"domain": "example.com", "static_evidence": ["hardcoded_domain"]}
                ]
            },
        )

        finding = report["findings"][0]
        self.assertEqual(finding["status"], "Supported")
        self.assertEqual(finding["confidence"], "medium")
        self.assertEqual(report["observations"][0]["source"], "pcapdroid")

    def test_sensitive_category_is_supported_only_when_dynamically_observed(self):
        report = build_integrated_report(
            [
                {
                    "event_id": "E001",
                    "observability_status": "observed",
                    "domain": "api.example.com",
                    "data_categories": "location",
                    "risk": "High",
                    "risk_category": "個人情報らしいキー",
                    "risk_rule": "sensitive_key",
                }
            ],
            {"sensitive_data_categories": ["location", "contacts"]},
        )

        by_category = {item["category"]: item for item in report["findings"]}
        self.assertEqual(by_category["個人情報らしいキー"]["status"], "Supported")
        self.assertEqual(by_category["contacts"]["status"], "Potential")

    def test_tunnel_or_unattributed_traffic_remains_unverified(self):
        report = build_integrated_report(
            [
                {
                    "event_id": "E001",
                    "observability_status": "tunnel_only",
                    "capture_detail": "https_connect_tunnel",
                    "traffic_owner": "unknown",
                    "owner_confidence": "unknown",
                    "domain": "firestore.googleapis.com",
                    "risk": "Unknown",
                    "risk_category": "HTTPSトンネルのみ観測",
                    "risk_rule": "https_tunnel_only",
                }
            ],
            {},
            {"overall": "partial", "connect_tunnels_observed": 1},
        )

        self.assertEqual(report["findings"][0]["status"], "Unverified")
        self.assertEqual(report["capture_health"]["overall"], "partial")


if __name__ == "__main__":
    unittest.main()
