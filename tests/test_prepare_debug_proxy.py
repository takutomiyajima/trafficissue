import ssl
import tempfile
import unittest
from pathlib import Path

import prepare_debug_proxy


TEST_PEM = """-----BEGIN CERTIFICATE-----
AQIDBA==
-----END CERTIFICATE-----
"""


class PrepareDebugProxyTest(unittest.TestCase):
    def make_module(self, root: Path) -> Path:
        module = root / "app"
        manifest = module / "src" / "main" / "AndroidManifest.xml"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("<manifest />\n", encoding="utf-8")
        return module

    def test_creates_only_debug_variant_files_and_converts_pem(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            module = self.make_module(root)
            certificate = root / "mitmproxy-ca-cert.pem"
            certificate.write_text(TEST_PEM, encoding="ascii")

            paths = prepare_debug_proxy.install_debug_proxy_config(module, certificate)

            self.assertEqual(len(paths), 3)
            self.assertTrue(all(module / "src" / "debug" in path.parents for path in paths))
            self.assertEqual(
                (module / "src/debug/res/raw/mitmproxy_ca.cer").read_bytes(),
                ssl.PEM_cert_to_DER_cert(TEST_PEM),
            )
            config = (module / "src/debug/res/xml/network_security_config.xml").read_text()
            self.assertIn('<certificates src="system" />', config)
            self.assertIn('<certificates src="@raw/mitmproxy_ca" />', config)
            self.assertIn('cleartextTrafficPermitted="false"', config)
            manifest = (module / "src/debug/AndroidManifest.xml").read_text()
            self.assertIn('android:networkSecurityConfig="@xml/network_security_config"', manifest)
            self.assertEqual((module / "src/main/AndroidManifest.xml").read_text(), "<manifest />\n")

    def test_refuses_to_replace_conflicting_debug_manifest_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            module = self.make_module(root)
            debug_manifest = module / "src/debug/AndroidManifest.xml"
            debug_manifest.parent.mkdir(parents=True)
            debug_manifest.write_text("<manifest custom='true' />", encoding="utf-8")
            certificate = root / "ca.cer"
            certificate.write_bytes(b"der-certificate")

            with self.assertRaises(FileExistsError):
                prepare_debug_proxy.install_debug_proxy_config(module, certificate)
            self.assertEqual(debug_manifest.read_text(), "<manifest custom='true' />")
            self.assertFalse((module / "src/debug/res/raw/mitmproxy_ca.cer").exists())

    def test_requires_android_source_module_instead_of_apk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "P02.apk"
            apk.write_bytes(b"apk")
            certificate = root / "ca.cer"
            certificate.write_bytes(b"der")

            with self.assertRaisesRegex(ValueError, "module directory"):
                prepare_debug_proxy.install_debug_proxy_config(apk, certificate)


if __name__ == "__main__":
    unittest.main()
