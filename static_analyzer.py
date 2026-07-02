from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence


STATIC_COLUMNS = ["apk", "package", "signal_type", "name", "value", "evidence"]
URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
DOMAIN_RE = re.compile(rb"(?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|jp|co|dev|app|googleapis\.com|firebaseio\.com)\b")
BADGING_KEY_RE = re.compile(r"(\w+)='([^']*)'")
COMPONENT_RE = re.compile(r"^(activity|service|receiver|provider)(?:-alias)?: name='([^']+)'")
LAUNCHABLE_RE = re.compile(r"^launchable-activity: name='([^']+)'")

PERMISSION_CATEGORIES = {
    "android.permission.ACCESS_FINE_LOCATION": ("location", True),
    "android.permission.ACCESS_COARSE_LOCATION": ("location", True),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("location", True),
    "android.permission.READ_CONTACTS": ("contacts", True),
    "android.permission.WRITE_CONTACTS": ("contacts", True),
    "android.permission.GET_ACCOUNTS": ("personal_info", True),
    "android.permission.READ_CALENDAR": ("calendar", True),
    "android.permission.WRITE_CALENDAR": ("calendar", True),
    "android.permission.CAMERA": ("photos_videos", True),
    "android.permission.RECORD_AUDIO": ("audio", True),
    "android.permission.READ_PHONE_STATE": ("device_identifier", True),
    "android.permission.READ_PHONE_NUMBERS": ("personal_info", True),
    "android.permission.READ_SMS": ("messages", True),
    "android.permission.SEND_SMS": ("messages", True),
    "android.permission.INTERNET": ("network", False),
    "android.permission.ACCESS_NETWORK_STATE": ("network", False),
}

SENSITIVE_API_HINTS = {
    "location": ("LocationManager", "FusedLocationProviderClient", "requestLocationUpdates", "getLastKnownLocation", "getLastLocation"),
    "contacts": ("ContactsContract",),
    "device_identifier": ("Settings$Secure", "getDeviceId", "getImei", "ANDROID_ID"),
    "camera": ("android.hardware.Camera", "CameraManager", "camera2"),
    "audio": ("MediaRecorder", "AudioRecord"),
}
NETWORK_API_HINTS = {
    "http": ("OkHttpClient", "HttpURLConnection", "Retrofit", "Volley", "HttpClient"),
    "webview": ("WebView", "loadUrl", "postUrl"),
    "socket": ("java.net.Socket", "DatagramSocket", "SSLSocket"),
}
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
def find_android_tool(tool_name: str) -> Optional[str]:
    """PATHまたはAndroid SDK内からaapt/aapt2を検索する。"""

    # PATHから検索
    path_tool = shutil.which(tool_name)
    if path_tool:
        return path_tool

    sdk_candidates = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        str(Path.home() / "Library" / "Android" / "sdk"),  # macOS
        str(Path.home() / "Android" / "Sdk"),             # Linux
    ]

    for sdk_path in sdk_candidates:
        if not sdk_path:
            continue

        build_tools = Path(sdk_path) / "build-tools"

        if not build_tools.exists():
            continue

        version_dirs = sorted(
            (path for path in build_tools.iterdir() if path.is_dir()),
            key=lambda path: path.name,
            reverse=True,
        )

        for version_dir in version_dirs:
            candidate = version_dir / tool_name

            if candidate.exists() and os.access(candidate, os.X_OK):
                return str(candidate)

    return None

def run_tool(command: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def aapt_badging(apk_path: str) -> tuple[str, Dict[str, object]]:
    """aapt/aapt2を実行してAPKのbadging情報を取得する。"""

    errors: List[str] = []

    for tool_name in ("aapt", "aapt2"):
        tool_path = find_android_tool(tool_name)

        if not tool_path:
            errors.append(f"{tool_name}: tool not found")
            continue

        proc = run_tool([tool_path, "dump", "badging", apk_path])

        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout, {
                "status": "success",
                "tool": tool_path,
                "message": "",
            }

        errors.append(
            f"{tool_name}: exit={proc.returncode}, "
            f"stderr={proc.stderr.strip()}"
        )

    return "", {
        "status": "failed",
        "tool": None,
        "message": " | ".join(errors),
    }


def extract_package(badging: str) -> str:
    match = re.search(r"package: name='([^']+)'", badging)
    return match.group(1) if match else ""


def parse_badging_keys(line: str) -> Dict[str, str]:
    return dict(BADGING_KEY_RE.findall(line))


def extract_permissions(badging: str) -> Iterable[str]:
    for match in re.finditer(r"uses-permission(?:-sdk-\d+)?: name='([^']+)'", badging):
        yield match.group(1)


def byte_strings(apk_path: str, min_len: int = 4) -> List[bytes]:
    data = Path(apk_path).read_bytes()
    return re.findall(rb"[ -~]{%d,}" % min_len, data)


def safe_decode(value: bytes) -> str:
    return value.decode("utf-8", errors="ignore").strip("\x00")


def categorize_permission(permission: str) -> Dict[str, object]:
    category, sensitive = PERMISSION_CATEGORIES.get(permission, ("other", False))
    return {"name": permission, "category": category, "sensitive": sensitive}


def parse_application(badging: str, apk_path: str) -> Dict[str, object]:
    package_line = next((line for line in badging.splitlines() if line.startswith("package:")), "")
    sdk_line = next((line for line in badging.splitlines() if line.startswith("sdkVersion:")), "")
    target_line = next((line for line in badging.splitlines() if line.startswith("targetSdkVersion:")), "")
    app_label_line = next((line for line in badging.splitlines() if line.startswith("application-label:")), "")
    package_keys = parse_badging_keys(package_line)
    return {
        "apk_path": str(Path(apk_path).resolve()),
        "apk_file_name": Path(apk_path).name,
        "sha256": hashlib.sha256(Path(apk_path).read_bytes()).hexdigest(),
        "file_size_bytes": Path(apk_path).stat().st_size,
        "package_name": package_keys.get("name") or None,
        "version_name": package_keys.get("versionName") or None,
        "version_code": package_keys.get("versionCode") or None,
        "app_label": parse_badging_keys(app_label_line).get("label") or None,
        "min_sdk": parse_badging_keys(sdk_line).get("sdkVersion") or None,
        "target_sdk": parse_badging_keys(target_line).get("targetSdkVersion") or None,
        "debuggable": (
            "application-debuggable" in badging
            if badging
            else None
        ),
    }


def parse_components(badging: str) -> List[Dict[str, object]]:
    components: List[Dict[str, object]] = []
    launchable = {match.group(1) for match in LAUNCHABLE_RE.finditer(badging)}
    for line in badging.splitlines():
        match = COMPONENT_RE.match(line)
        if not match:
            continue
        component_type, name = match.groups()
        keys = parse_badging_keys(line)
        exported = keys.get("exported")
        components.append(
            {
                "type": "broadcast_receiver" if component_type == "receiver" else component_type,
                "name": name,
                "exported": exported.lower() == "true" if exported else name in launchable,
                "protected_by_permission": bool(keys.get("permission")),
                "permission": keys.get("permission", ""),
                "deep_links": [],
            }
        )
    for name in launchable:
        if not any(item["name"] == name for item in components):
            components.append({"type": "activity", "name": name, "exported": True, "protected_by_permission": False, "permission": "", "deep_links": []})
    return components


def detect_hints(decoded_strings: List[str], hints: Dict[str, Sequence[str]]) -> Dict[str, List[str]]:
    joined_lower = "\n".join(decoded_strings).lower()
    detected: Dict[str, List[str]] = {}
    for name, needles in hints.items():
        hits = sorted({needle for needle in needles if needle.lower() in joined_lower})
        if hits:
            detected[name] = hits
    return detected


def build_json_report(
    apk_path: str,
    badging: str,
    findings: List[StaticFinding],
    decoded_strings: List[str],
    manifest_status: Dict[str, object],
) -> Dict[str, object]:
    permissions = [categorize_permission(permission) for permission in sorted(set(extract_permissions(badging)))]
    components = parse_components(badging)
    sensitive_api_hints = detect_hints(decoded_strings, SENSITIVE_API_HINTS)
    network_api_hints = detect_hints(decoded_strings, NETWORK_API_HINTS)
    sdk_hints = detect_hints(decoded_strings, SDK_HINTS)
    return {
    "analysis_status": (
        "success"
        if manifest_status["status"] == "success"
        else "partial"
    ),
    "stages": {
        "file_analysis": {
            "status": "success",
        },
        "manifest_analysis": manifest_status,
        "string_analysis": {
            "status": "success",
        },
    },
    "application": parse_application(badging, apk_path),
    "permissions": permissions,
    "components": components,
    "component_summary": summarize_components(components),
    "sensitive_api_hints": sensitive_api_hints,
    "network_api_hints": network_api_hints,
    "sdk_hints": sdk_hints,
    "findings": [asdict(finding) for finding in findings],
}


def summarize_components(components: List[Dict[str, object]]) -> Dict[str, Dict[str, int]]:
    summary: Dict[str, Dict[str, int]] = {}
    for item in components:
        key = str(item["type"])
        summary.setdefault(key, {"total": 0, "exported": 0, "unprotected_exported": 0})
        summary[key]["total"] += 1
        if item.get("exported"):
            summary[key]["exported"] += 1
            if not item.get("protected_by_permission"):
                summary[key]["unprotected_exported"] += 1
    return summary

def is_plausible_domain(domain: str) -> bool:
    domain = domain.lower().strip(".")

    if len(domain) < 7:
        return False

    labels = domain.split(".")

    if len(labels) < 2:
        return False

    if any(not label for label in labels):
        return False

    if len(labels[-2]) <= 2:
        return False

    return True

def analyze_static(
    apk_path: str,
    output_path: str = "logs/static_analysis.csv",
    json_output_path: Optional[str] = None,
) -> List[StaticFinding]:
    apk_path = str(Path(apk_path).resolve())

    if not os.path.exists(apk_path):
        raise FileNotFoundError(
            f"APK file not found: {apk_path}"
        )

    badging, manifest_status = aapt_badging(apk_path)
    package_name = extract_package(badging)
    findings: List[StaticFinding] = []

    def add(
        signal_type: str,
        name: str,
        value: str,
        evidence: str,
    ) -> None:
        finding = StaticFinding(
            apk_path,
            package_name,
            signal_type,
            name,
            value,
            evidence,
        )

        if finding not in findings:
            findings.append(finding)

    if manifest_status["status"] != "success":
        add(
            "analysis_error",
            "manifest_analysis_failed",
            str(manifest_status["message"]),
            "aapt/aapt2 could not parse APK manifest",
        )

    application = parse_application(
        badging,
        apk_path,
    )

    if application["sha256"]:
        add(
            "apk",
            "sha256",
            str(application["sha256"]),
            "APK file hash",
        )

    if package_name:
        add(
            "manifest",
            "package",
            package_name,
            "aapt dump badging",
        )

    for key in (
        "version_name",
        "version_code",
        "min_sdk",
        "target_sdk",
        "app_label",
    ):
        if application.get(key):
            add(
                "manifest",
                key,
                str(application[key]),
                "aapt dump badging",
            )

    for permission in sorted(
        set(extract_permissions(badging))
    ):
        category = categorize_permission(permission)

        add(
            "permission",
            permission.rsplit(".", 1)[-1],
            permission,
            (
                "AndroidManifest.xml "
                f"category={category['category']} "
                f"sensitive={category['sensitive']}"
            ),
        )

    for component in parse_components(badging):
        add(
            "component",
            str(component["type"]),
            str(component["name"]),
            (
                f"exported={component['exported']} "
                f"protected_by_permission="
                f"{component['protected_by_permission']}"
            ),
        )

    raw_data = Path(apk_path).read_bytes()
    strings = byte_strings(apk_path)
    decoded_strings = [
        safe_decode(item)
        for item in strings
    ]
    joined_lower = "\n".join(
        decoded_strings
    ).lower()

    for raw_url in sorted(
        set(URL_RE.findall(raw_data))
    ):
        add(
            "url",
            "hardcoded_url",
            safe_decode(raw_url),
            "APK string table / byte strings",
        )

    for raw_domain in sorted(
        set(DOMAIN_RE.findall(raw_data))
    ):
        domain = safe_decode(
            raw_domain
        ).lower()

        if domain.startswith(
            ("http", "android.")
        ):
            continue

        if not is_plausible_domain(domain):
            continue

        add(
            "domain",
            "hardcoded_domain",
            domain,
            "Raw APK byte candidate; low-confidence evidence",
        )

    if (
        'android:usescleartexttraffic="true"'
        in joined_lower
        or "usescleartexttraffic" in joined_lower
    ):
        add(
            "network_security",
            "cleartext_hint",
            "usesCleartextTraffic reference found",
            "APK strings",
        )

    if "network_security_config" in joined_lower:
        add(
            "network_security",
            "network_security_config",
            "network_security_config reference found",
            "APK strings",
        )

    for category, hits in detect_hints(
        decoded_strings,
        SENSITIVE_API_HINTS,
    ).items():
        add(
            "sensitive_api_hint",
            category,
            ";".join(hits),
            "APK strings",
        )

    for category, hits in detect_hints(
        decoded_strings,
        NETWORK_API_HINTS,
    ).items():
        add(
            "network_api_hint",
            category,
            ";".join(hits),
            "APK strings",
        )

    for sdk_name, hits in detect_hints(
        decoded_strings,
        SDK_HINTS,
    ).items():
        add(
            "sdk_hint",
            sdk_name,
            ";".join(hits),
            "APK strings",
        )

    output = Path(output_path)
    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.writer(file)
        writer.writerow(STATIC_COLUMNS)

        for finding in findings:
            writer.writerow(finding.row())

    if json_output_path:
        json_output = Path(json_output_path)
        json_output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        report = build_json_report(
            apk_path,
            badging,
            findings,
            decoded_strings,
            manifest_status,
        )

        json_output.write_text(
            json.dumps(
                report,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        print(
            f"[Static] Saved JSON report to "
            f"{json_output}"
        )

    print(
        f"[Static] Saved {len(findings)} "
        f"finding(s) to {output}"
    )

    return findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract lightweight static privacy signals from an APK.")
    parser.add_argument("apk", help="Path to APK file.")
    parser.add_argument("--output", default="logs/static_analysis.csv", help="CSV output path.")
    parser.add_argument("--json-output", default="logs/static_analysis.json", help="JSON report output path.")
    return parser.parse_args() 

if __name__ == "__main__":
    args = parse_args()
    analyze_static(args.apk, args.output, args.json_output)
