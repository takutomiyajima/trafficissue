import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import static_analyzer


class StaticAnalyzerTest(unittest.TestCase):
    def test_analyze_static_extracts_urls_domains_sdk_hints_and_badging_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            apk = base / "sample.apk"
            output = base / "static_analysis.csv"
            with zipfile.ZipFile(apk, "w") as apk_zip:
                apk_zip.writestr(
                    "classes.dex",
                    b"https://maps.googleapis.com/maps/api\x00"
                    b"com.google.android.gms.ads.MobileAds\x00network_security_config\x00",
                )
            badging = (
                "package: name='com.example.app' versionCode='1' versionName='1.0'\n"
                "sdkVersion:'23'\n"
                "targetSdkVersion:'35'\n"
                "application-label:'Research Demo'\n"
                "uses-permission: name='android.permission.INTERNET'\n"
                "uses-permission: name='android.permission.ACCESS_FINE_LOCATION'\n"
            )
            manifest_status = {"status": "success", "tool": "/tmp/aapt", "message": ""}
            component_status = {"status": "failed", "tool": None, "message": "apkanalyzer was not found"}

            json_output = base / "static_analysis.json"
            with patch("static_analyzer.aapt_badging", return_value=(badging, manifest_status)), patch(
                "static_analyzer.get_manifest_xml", return_value=("", component_status)
            ):
                findings = static_analyzer.analyze_static(str(apk), str(output), str(json_output))

            rows = [finding.row() for finding in findings]
            flat = "\n".join(",".join(row) for row in rows)
            self.assertIn("com.example.app", flat)
            self.assertIn("android.permission.INTERNET", flat)
            self.assertIn("android.permission.ACCESS_FINE_LOCATION", flat)
            self.assertIn("https://maps.googleapis.com/maps/api", flat)
            self.assertIn("source_file=classes.dex", flat)
            self.assertIn("confidence=low", flat)
            self.assertIn("Google Maps", flat)
            self.assertIn("AdMob", flat)
            self.assertIn("network_security_config", flat)
            self.assertIn("Research Demo", flat)
            self.assertIn("target_sdk", flat)
            self.assertTrue(output.exists())
            report = json.loads(json_output.read_text(encoding="utf-8"))
            self.assertEqual(report["application"]["package_name"], "com.example.app")
            self.assertEqual(report["application"]["app_label"], "Research Demo")
            self.assertEqual(report["application"]["min_sdk"], "23")
            self.assertEqual(report["application"]["target_sdk"], "35")
            self.assertEqual(report["stages"]["manifest_badging_analysis"], manifest_status)
            self.assertEqual(report["stages"]["manifest_xml_analysis"], component_status)
            permission_by_name = {item["name"]: item for item in report["permissions"]}
            self.assertEqual(permission_by_name["android.permission.ACCESS_FINE_LOCATION"]["category"], "location")
            self.assertTrue(permission_by_name["android.permission.ACCESS_FINE_LOCATION"]["sensitive"])
            self.assertIn("admob", "\n".join(report["sdk_hints"].keys()).lower().replace(" ", "_"))
            self.assertNotIn("sensitive_api_hints", report)
            self.assertIn("sensitive_api_string_hints", report)

    def test_parse_manifest_components_extracts_exported_permissions_and_deep_links(self):
        manifest_xml = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application>
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <data android:scheme="demo" android:host="example.com" android:pathPrefix="/open" />
      </intent-filter>
    </activity>
    <service android:name=".SyncService" android:permission="com.example.PRIVATE" />
    <receiver android:name=".BootReceiver">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED" />
      </intent-filter>
    </receiver>
  </application>
</manifest>'''

        components = static_analyzer.parse_manifest_components(manifest_xml)

        self.assertEqual(len(components), 3)
        by_name = {component["name"]: component for component in components}
        self.assertTrue(by_name[".MainActivity"]["exported"])
        self.assertTrue(by_name[".MainActivity"]["is_launcher"])
        self.assertIn("android.intent.action.MAIN", by_name[".MainActivity"]["actions"])
        self.assertIn("android.intent.category.LAUNCHER", by_name[".MainActivity"]["categories"])
        self.assertEqual(
            by_name[".MainActivity"]["deep_links"],
            [{"scheme": "demo", "host": "example.com", "path": "/open"}],
        )
        self.assertFalse(by_name[".SyncService"]["exported"])
        self.assertTrue(by_name[".SyncService"]["protected_by_permission"])
        self.assertTrue(by_name[".BootReceiver"]["exported"])

        summary = static_analyzer.summarize_components(components)
        self.assertEqual(summary["activity"]["exported"], 1)
        self.assertEqual(summary["activity"]["unprotected_exported"], 0)

    def test_find_apkanalyzer_prefers_cmdline_tools_and_ignores_legacy_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            sdk = Path(tmp)
            latest = sdk / "cmdline-tools" / "latest" / "bin" / "apkanalyzer"
            versioned = sdk / "cmdline-tools" / "12.0" / "bin" / "apkanalyzer"
            legacy = sdk / "tools" / "bin" / "apkanalyzer"

            for candidate in (latest, versioned, legacy):
                candidate.parent.mkdir(parents=True, exist_ok=True)
                candidate.write_text("#!/bin/sh\n", encoding="utf-8")
                candidate.chmod(0o755)

            with patch("static_analyzer.shutil.which", return_value=None), patch.dict(
                "static_analyzer.os.environ",
                {"ANDROID_HOME": str(sdk), "ANDROID_SDK_ROOT": ""},
            ), patch("static_analyzer.Path.home", return_value=Path("/unused")):
                self.assertEqual(static_analyzer.find_apkanalyzer(), str(latest))

            latest.unlink()

            with patch("static_analyzer.shutil.which", return_value=None), patch.dict(
                "static_analyzer.os.environ",
                {"ANDROID_HOME": str(sdk), "ANDROID_SDK_ROOT": ""},
            ), patch("static_analyzer.Path.home", return_value=Path("/unused")):
                self.assertEqual(static_analyzer.find_apkanalyzer(), str(versioned))

            versioned.unlink()

            with patch("static_analyzer.shutil.which", return_value=None), patch.dict(
                "static_analyzer.os.environ",
                {"ANDROID_HOME": str(sdk), "ANDROID_SDK_ROOT": ""},
            ), patch("static_analyzer.Path.home", return_value=Path("/unused")):
                self.assertIsNone(static_analyzer.find_apkanalyzer())

    def test_clean_url_and_host_extraction_filters_noise_and_documentation(self):
        self.assertEqual(
            static_analyzer.clean_url_candidate("https://api.myapp.test/path);"),
            "https://api.myapp.test/path",
        )
        self.assertIsNone(static_analyzer.clean_url_candidate("http://a"))
        self.assertIsNone(static_analyzer.clean_url_candidate("http://localhost:8080"))

        hosts = static_analyzer.extract_candidate_hosts(
            [
                "docs https://dart.dev/tools and https://api.flutter.dev/widgets",
                "runtime https://api.myapp.test/v1 and http://127.0.0.1:1234",
                "analytics https://firebaseinstallations.googleapis.com/project",
            ]
        )

        self.assertEqual(
            hosts,
            ["api.myapp.test", "firebaseinstallations.googleapis.com"],
        )


if __name__ == "__main__":
    unittest.main()
