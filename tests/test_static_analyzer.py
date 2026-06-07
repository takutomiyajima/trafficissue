import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import static_analyzer


class StaticAnalyzerTest(unittest.TestCase):
    def test_analyze_static_extracts_urls_domains_sdk_hints_and_badging_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            apk = base / "sample.apk"
            output = base / "static_analysis.csv"
            apk.write_bytes(
                b"classes.dex\x00https://maps.googleapis.com/maps/api\x00"
                b"com.google.android.gms.ads.MobileAds\x00network_security_config\x00"
            )
            badging = (
                "package: name='com.example.app' versionCode='1'\n"
                "uses-permission: name='android.permission.INTERNET'\n"
                "uses-permission: name='android.permission.ACCESS_FINE_LOCATION'\n"
            )

            with patch("static_analyzer.aapt_badging", return_value=badging):
                findings = static_analyzer.analyze_static(str(apk), str(output))

            rows = [finding.row() for finding in findings]
            flat = "\n".join(",".join(row) for row in rows)
            self.assertIn("com.example.app", flat)
            self.assertIn("android.permission.INTERNET", flat)
            self.assertIn("android.permission.ACCESS_FINE_LOCATION", flat)
            self.assertIn("https://maps.googleapis.com/maps/api", flat)
            self.assertIn("Google Maps", flat)
            self.assertIn("AdMob", flat)
            self.assertIn("network_security_config", flat)
            self.assertTrue(output.exists())


if __name__ == "__main__":
    unittest.main()
