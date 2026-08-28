"""Opt-in integration test that runs the analyzer against a real APK file."""

import csv
import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

import static_analyzer


REAL_APK_ENV = "TRAFFICISSUE_TEST_APK"


class RealApkStaticAnalyzerTest(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get(REAL_APK_ENV),
        f"Set {REAL_APK_ENV} to run the real-APK integration test",
    )
    def test_analyze_real_apk_file_end_to_end(self):
        apk = Path(os.environ[REAL_APK_ENV]).expanduser().resolve()
        self.assertTrue(apk.is_file(), f"APK does not exist: {apk}")
        self.assertTrue(zipfile.is_zipfile(apk), f"Not an APK/ZIP file: {apk}")

        with zipfile.ZipFile(apk) as archive:
            self.assertIn("AndroidManifest.xml", archive.namelist())

        with tempfile.TemporaryDirectory() as tmp:
            csv_output = Path(tmp) / "static_analysis.csv"
            json_output = Path(tmp) / "static_analysis.json"

            findings = static_analyzer.analyze_static(
                str(apk),
                str(csv_output),
                str(json_output),
            )

            report = json.loads(json_output.read_text(encoding="utf-8"))
            expected_hash = hashlib.sha256(apk.read_bytes()).hexdigest()
            self.assertEqual(report["application"]["sha256"], expected_hash)
            self.assertEqual(report["application"]["apk_file_name"], apk.name)
            self.assertIn(report["analysis_status"], {"success", "partial"})
            self.assertIn("manifest_badging_analysis", report["stages"])
            self.assertEqual(len(report["findings"]), len(findings))

            with csv_output.open(encoding="utf-8", newline="") as file:
                rows = list(csv.DictReader(file))
            self.assertEqual(len(rows), len(findings))
            self.assertTrue(any(row["signal_type"] == "apk" for row in rows))


if __name__ == "__main__":
    unittest.main()
