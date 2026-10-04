"""Create debug-only Android resources for trusting a mitmproxy CA.

This utility intentionally operates on an Android source module. It never
modifies an APK or any file under ``src/main`` so experiment artifacts remain
unchanged.
"""

import argparse
import os
import ssl
import sys
import tempfile
from pathlib import Path


NETWORK_SECURITY_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="@raw/mitmproxy_ca" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
"""

DEBUG_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:networkSecurityConfig="@xml/network_security_config"
        android:usesCleartextTraffic="false" />
</manifest>
"""


def certificate_as_der(certificate: Path) -> bytes:
    """Read a PEM/DER certificate and return bytes suitable for a .cer resource."""
    data = certificate.read_bytes()
    if not data:
        raise ValueError(f"CA certificate is empty: {certificate}")
    if b"-----BEGIN CERTIFICATE-----" in data:
        try:
            return ssl.PEM_cert_to_DER_cert(data.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError(f"Invalid PEM certificate: {certificate}") from exc
    return data


def debug_files(module: Path, certificate: Path) -> dict[Path, bytes]:
    debug = module / "src" / "debug"
    return {
        debug / "res" / "raw" / "mitmproxy_ca.cer": certificate_as_der(certificate),
        debug / "res" / "xml" / "network_security_config.xml": NETWORK_SECURITY_CONFIG.encode(),
        debug / "AndroidManifest.xml": DEBUG_MANIFEST.encode(),
    }


def write_atomically(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def install_debug_proxy_config(module: Path, certificate: Path, force: bool = False) -> list[Path]:
    module = module.resolve()
    certificate = certificate.resolve()
    if not module.is_dir():
        raise ValueError(f"Android app module directory does not exist: {module}")
    if not (module / "src" / "main" / "AndroidManifest.xml").is_file():
        raise ValueError(f"Android app module must contain src/main/AndroidManifest.xml: {module}")
    if not certificate.is_file():
        raise ValueError(f"CA certificate does not exist: {certificate}")

    files = debug_files(module, certificate)
    conflicts = [path for path, content in files.items() if path.exists() and path.read_bytes() != content]
    if conflicts and not force:
        joined = ", ".join(str(path) for path in conflicts)
        raise FileExistsError(
            f"Refusing to overwrite existing debug configuration: {joined}. Use --force to replace it."
        )

    for path, content in files.items():
        if not path.exists() or path.read_bytes() != content:
            write_atomically(path, content)
    return list(files)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Add a mitmproxy CA to an Android source project's debug variant only."
    )
    parser.add_argument("module", type=Path, help="Android application module directory (for example, ./app).")
    parser.add_argument("certificate", type=Path, help="mitmproxy CA certificate in PEM or DER format.")
    parser.add_argument("--force", action="store_true", help="Replace conflicting files already present under src/debug.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    paths = install_debug_proxy_config(args.module, args.certificate, force=args.force)
    print("Created debug-only network security configuration:")
    for path in paths:
        print(f"  {path}")
    print("Build a debug variant; do not use this build as a P00-P04 evaluation artifact.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
