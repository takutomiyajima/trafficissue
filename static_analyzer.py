from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence


STATIC_COLUMNS = ["apk", "package", "signal_type", "name", "value", "evidence"]
URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
DOMAIN_RE = re.compile(rb"(?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|jp|co|dev|app|googleapis\.com|firebaseio\.com)\b")
SDK_HINTS = {
    "Firebase": ("firebase", "google.firebase"),
    "Google Maps": ("maps.googleapis.com", "com.google.android.gms.maps"),
    "AdMob": ("admob", "google.android.gms.ads", "doubleclick.net"),
    "Google Analytics": ("google-analytics.com", "app-measurement.com", "firebase.analytics"),
    "Facebook SDK": ("facebook.com", "com.facebook"),
    "Adjust": ("adjust.com", "com.adjust"),
    "AppsFlyer": ("appsflyer.com", "com.appsflyer"),
}


@dataclass(frozen=True)
class StaticFinding:
    apk: str
    package: str
    signal_type: str
    name: str
    value: str
    evidence: str

    def row(self) -> List[str]:
        return [self.apk, self.package, self.signal_type, self.name, self.value, self.evidence]


def run_tool(command: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def aapt_badging(apk_path: str) -> str:
    for tool in ("aapt", "aapt2"):
        if shutil.which(tool):
            proc = run_tool([tool, "dump", "badging", apk_path])
            if proc.returncode == 0 and proc.stdout:
                return proc.stdout
    return ""


def extract_package(badging: str) -> str:
    match = re.search(r"package: name='([^']+)'", badging)
    return match.group(1) if match else ""


def extract_permissions(badging: str) -> Iterable[str]:
    for match in re.finditer(r"uses-permission(?:-sdk-\d+)?: name='([^']+)'", badging):
        yield match.group(1)


def byte_strings(apk_path: str, min_len: int = 4) -> List[bytes]:
    data = Path(apk_path).read_bytes()
    return re.findall(rb"[ -~]{%d,}" % min_len, data)


def safe_decode(value: bytes) -> str:
    return value.decode("utf-8", errors="ignore").strip("\x00")


def analyze_static(apk_path: str, output_path: str = "logs/static_analysis.csv") -> List[StaticFinding]:
    apk_path = str(Path(apk_path).resolve())
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    badging = aapt_badging(apk_path)
    package_name = extract_package(badging)
    findings: List[StaticFinding] = []

    def add(signal_type: str, name: str, value: str, evidence: str) -> None:
        finding = StaticFinding(apk_path, package_name, signal_type, name, value, evidence)
        if finding not in findings:
            findings.append(finding)

    if package_name:
        add("manifest", "package", package_name, "aapt dump badging")
    for permission in sorted(set(extract_permissions(badging))):
        add("permission", permission.rsplit(".", 1)[-1], permission, "AndroidManifest.xml")

    strings = byte_strings(apk_path)
    decoded_strings = [safe_decode(item) for item in strings]
    joined_lower = "\n".join(decoded_strings).lower()

    for raw_url in sorted(set(URL_RE.findall(Path(apk_path).read_bytes()))):
        add("url", "hardcoded_url", safe_decode(raw_url), "APK string table / byte strings")
    for raw_domain in sorted(set(DOMAIN_RE.findall(Path(apk_path).read_bytes()))):
        domain = safe_decode(raw_domain).lower()
        if not domain.startswith(("http", "android.")):
            add("domain", "hardcoded_domain", domain, "APK string table / byte strings")

    if "android:usescleartexttraffic=\"true\"" in joined_lower or "usescleartexttraffic" in joined_lower:
        add("network_security", "cleartext_hint", "usesCleartextTraffic reference found", "APK strings")
    if "network_security_config" in joined_lower:
        add("network_security", "network_security_config", "network_security_config reference found", "APK strings")

    for sdk_name, needles in SDK_HINTS.items():
        if any(needle.lower() in joined_lower for needle in needles):
            add("sdk_hint", sdk_name, ";".join(needles), "APK strings")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(STATIC_COLUMNS)
        for finding in findings:
            writer.writerow(finding.row())
    print(f"[Static] Saved {len(findings)} finding(s) to {output}")
    return findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract lightweight static risk signals from an APK.")
    parser.add_argument("apk", help="Path to APK file.")
    parser.add_argument("--output", default="logs/static_analysis.csv", help="CSV output path.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    analyze_static(args.apk, args.output)
