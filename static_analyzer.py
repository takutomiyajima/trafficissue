from __future__ import annotations

import argparse
import csv
from contextlib import contextmanager
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence


STATIC_COLUMNS = ["apk", "package", "signal_type", "name", "value", "evidence"]
URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
DOMAIN_RE = re.compile(rb"(?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|jp|co|dev|app|googleapis\.com|firebaseio\.com)\b")
BADGING_KEY_RE = re.compile(r"(\w+)='([^']*)'")
COMPONENT_RE = re.compile(r"^(activity|service|receiver|provider)(?:-alias)?: name='([^']+)'")
ANDROID_NS = "http://schemas.android.com/apk/res/android"
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

CONFIG_DIR = Path(__file__).resolve().parent / "config"


class StaticAnalysisStageError(RuntimeError):
    """An actionable static-analysis failure with stage and input context."""

    def __init__(self, stage: str, apk_path: str, cause: BaseException):
        self.stage = stage
        self.apk_path = apk_path
        self.cause = cause
        super().__init__(f"static analysis failed at {stage} for {apk_path}: {cause}")


@contextmanager
def static_analysis_stage(stage: str, apk_path: str):
    try:
        yield
    except StaticAnalysisStageError:
        raise
    except Exception as exc:
        raise StaticAnalysisStageError(stage, apk_path, exc) from exc


def _yaml_scalar(value: str) -> object:
    """Parse the small, dependency-free YAML subset used by ``config/``."""

    value = value.strip()
    if value in {"true", "false"}:
        return value == "true"
    if value.startswith("[") and value.endswith("]"):
        return [item.strip().strip("'\"") for item in value[1:-1].split(",") if item.strip()]
    return value.strip("'\"")


def _load_signature_yaml(path: Path) -> Dict[str, object]:
    """Load the intentionally simple project YAML without requiring PyYAML."""

    result: Dict[str, object] = {}
    section: Optional[str] = None
    list_key: Optional[str] = None
    current_item: Optional[Dict[str, object]] = None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        text = line.strip()
        if indent == 0 and text.endswith(":"):
            section = text[:-1]
            result[section] = {}
            list_key = None
            current_item = None
        elif section and indent == 2 and text.startswith("- "):
            if not isinstance(result[section], list):
                result[section] = []
            values = result[section]
            assert isinstance(values, list)
            value = text[2:]
            key, item_value = value.split(":", 1)
            current_item = {key: _yaml_scalar(item_value)}
            values.append(current_item)
            list_key = None
        elif section and indent == 2 and text.endswith(":"):
            list_key = text[:-1]
            cast = result[section]
            assert isinstance(cast, dict)
            cast[list_key] = []
            current_item = None
        elif section and indent == 2 and ":" in text:
            key, value = text.split(":", 1)
            cast = result[section]
            assert isinstance(cast, dict)
            cast[key] = _yaml_scalar(value)
        elif section and indent >= 4 and text.startswith("- "):
            value = text[2:]
            cast = result[section]
            assert isinstance(cast, dict) and list_key
            values = cast[list_key]
            assert isinstance(values, list)
            if ":" in value:
                key, item_value = value.split(":", 1)
                current_item = {key: _yaml_scalar(item_value)}
                values.append(current_item)
            else:
                values.append(_yaml_scalar(value))
                current_item = None
        elif current_item is not None and indent >= 4 and ":" in text:
            key, value = text.split(":", 1)
            current_item[key] = _yaml_scalar(value)
    return result


def load_static_config(config_dir: Path | str = CONFIG_DIR) -> Dict[str, object]:
    """Load all static-analysis rules, failing clearly on an incomplete setup."""

    directory = Path(config_dir)
    names = ("permission_categories", "sensitive_apis", "network_apis", "sdk_signatures")
    config: Dict[str, object] = {}
    for name in names:
        path = directory / f"{name}.yml"
        if not path.is_file():
            raise FileNotFoundError(f"Static analysis config not found: {path}")
        config[name] = _load_signature_yaml(path)
    return config


def configured_permission_categories(config: Dict[str, object]) -> Dict[str, tuple[str, bool]]:
    result: Dict[str, tuple[str, bool]] = {}
    categories = config["permission_categories"]
    assert isinstance(categories, dict)
    for category, details in categories.items():
        assert isinstance(details, dict)
        for permission in details.get("permissions", []):
            result[str(permission)] = (category, bool(details.get("sensitive", False)))
    return result


def configured_api_hints(config_section: object) -> Dict[str, tuple[str, ...]]:
    result: Dict[str, tuple[str, ...]] = {}
    assert isinstance(config_section, dict)
    for category, details in config_section.items():
        api_items = details.get("apis", details) if isinstance(details, dict) else details
        if isinstance(api_items, list):
            values: List[str] = []
            for item in api_items:
                if not isinstance(item, dict):
                    continue
                values.append(str(item.get("class", "")).strip("L;"))
                values.extend(str(method) for method in item.get("methods", []))
            result[category] = tuple(value for value in values if value)
    return result


def detect_configured_api_hints(
    decoded_strings: List[str],
    config_section: object,
) -> Dict[str, List[str]]:
    """Detect API signatures only when their declaring class is present.

    Method names such as ``start``, ``add`` and ``query`` are too generic to be
    useful independently. Requiring the configured class prevents those common
    strings from producing unrelated privacy findings.
    """

    assert isinstance(config_section, dict)
    joined_lower = "\n".join(decoded_strings).lower()
    detected: Dict[str, List[str]] = {}
    for category, details in config_section.items():
        api_items = details.get("apis", details) if isinstance(details, dict) else details
        if not isinstance(api_items, list):
            continue
        hits: set[str] = set()
        for item in api_items:
            if not isinstance(item, dict):
                continue
            raw_class = str(item.get("class", ""))
            normalized_class = raw_class.strip("L;")
            class_variants = {
                raw_class.lower(),
                normalized_class.lower(),
                normalized_class.replace("/", ".").lower(),
            }
            if not normalized_class or not any(value in joined_lower for value in class_variants):
                continue
            hits.add(normalized_class)
            hits.update(
                str(method)
                for method in item.get("methods", [])
                if str(method).lower() in joined_lower
            )
        if hits:
            detected[category] = sorted(hits)
    return detected


def configured_sdk_hints(config_section: object) -> tuple[Dict[str, tuple[str, ...]], Dict[str, Dict[str, object]]]:
    hints: Dict[str, tuple[str, ...]] = {}
    metadata: Dict[str, Dict[str, object]] = {}
    assert isinstance(config_section, dict)
    for key, details in config_section.items():
        assert isinstance(details, dict)
        display_name = str(details.get("display_name", key))
        values = list(details.get("package_prefixes", [])) + list(details.get("related_domains", []))
        hints[display_name] = tuple(str(value) for value in values)
        metadata[display_name] = {"id": key, "category": details.get("category", "unknown")}
    return hints, metadata


IGNORED_URL_HOST_SUFFIXES = {
    "flutter.dev",
    "dart.dev",
    "dartlang.org",
    "flutter.github.io",
    "dartbug.com",
    "developer.android.com",
    "developer.apple.com",
    "developer.mozilla.org",
    "w3.org",
    "w3c.org",
    "iana.org",
    "unicode.org",
    "microsoft.com",
    "chromium.org",
    "googlesource.com",
}

IGNORED_EXACT_HOSTS = {
    "example.com",
    "example.org",
    "localhost",
    "127.0.0.1",
}

# Kept as a compatibility alias for callers/tests that imported the old name.
DOCUMENTATION_HOSTS = IGNORED_URL_HOST_SUFFIXES | IGNORED_EXACT_HOSTS


def should_ignore_url_host(hostname: str) -> bool:
    hostname = hostname.lower()

    if hostname in IGNORED_EXACT_HOSTS:
        return True

    return any(
        hostname == suffix or hostname.endswith("." + suffix)
        for suffix in IGNORED_URL_HOST_SUFFIXES
    )


def clean_url_candidate(value: str) -> Optional[str]:
    value = value.strip()
    value = value.rstrip("');,:")

    try:
        parsed = urlparse(value)
    except ValueError:
        return None

    if parsed.scheme not in {"http", "https"}:
        return None

    if not parsed.hostname:
        return None

    hostname = parsed.hostname.lower()

    if should_ignore_url_host(hostname):
        return None

    if "." not in hostname:
        return None

    if len(hostname) < 4:
        return None

    return value


def extract_candidate_hosts(decoded_strings: List[str]) -> List[str]:
    hosts: set[str] = set()

    for text in decoded_strings:
        for match in re.findall(r"https?://[^\s\"'<>]+", text):
            cleaned_url = clean_url_candidate(match)

            if not cleaned_url:
                continue

            host = urlparse(cleaned_url).hostname

            if not host:
                continue

            host = host.lower()

            if host in DOCUMENTATION_HOSTS:
                continue

            hosts.add(host)

    return sorted(hosts)

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


def find_apkanalyzer() -> Optional[str]:
    path_tool = shutil.which("apkanalyzer")

    if path_tool:
        return path_tool

    sdk_candidates = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        str(Path.home() / "Library" / "Android" / "sdk"),
        str(Path.home() / "Android" / "Sdk"),
    ]

    for sdk_path in sdk_candidates:
        if not sdk_path:
            continue

        sdk = Path(sdk_path)
        preferred_candidates = [
            sdk / "cmdline-tools" / "latest" / "bin" / "apkanalyzer",
        ]

        for candidate in preferred_candidates:
            if candidate.exists() and os.access(candidate, os.X_OK):
                return str(candidate)

        versioned_candidates = sorted(
            sdk.glob("cmdline-tools/*/bin/apkanalyzer"),
            key=lambda path: path.parent.parent.name,
            reverse=True,
        )

        for candidate in versioned_candidates:
            if (
                candidate.exists()
                and os.access(candidate, os.X_OK)
                and "latest" not in str(candidate)
            ):
                return str(candidate)

    return None


def get_manifest_xml(apk_path: str) -> tuple[str, Dict[str, object]]:
    tool = find_apkanalyzer()

    if not tool:
        return "", {
            "status": "failed",
            "tool": None,
            "message": "apkanalyzer was not found",
        }

    proc = run_tool([tool, "manifest", "print", apk_path])

    if proc.returncode != 0:
        return "", {
            "status": "failed",
            "tool": tool,
            "message": proc.stderr.strip(),
        }

    return proc.stdout, {
        "status": "success",
        "tool": tool,
        "message": "",
    }


def extract_package(badging: str) -> str:
    match = re.search(r"package: name='([^']+)'", badging)
    return match.group(1) if match else ""


def parse_badging_keys(line: str) -> Dict[str, str]:
    return dict(BADGING_KEY_RE.findall(line))


def extract_badging_value(badging: str, key: str) -> Optional[str]:
    pattern = rf"^{re.escape(key)}:'([^']*)'"

    for line in badging.splitlines():
        match = re.match(pattern, line.strip())

        if match:
            return match.group(1)

    return None


def extract_application_label(badging: str) -> Optional[str]:
    patterns = [
        r"^application-label:'([^']*)'",
        r"^application-label-[^:]+:'([^']*)'",
    ]

    for line in badging.splitlines():
        stripped = line.strip()

        for pattern in patterns:
            match = re.match(pattern, stripped)

            if match and match.group(1):
                return match.group(1)

    return None


def android_attr(name: str) -> str:
    return f"{{{ANDROID_NS}}}{name}"


def extract_permissions(badging: str) -> Iterable[str]:
    for match in re.finditer(r"uses-permission(?:-sdk-\d+)?: name='([^']+)'", badging):
        yield match.group(1)


def byte_strings(apk_path: str, min_len: int = 4) -> List[bytes]:
    data = Path(apk_path).read_bytes()
    return re.findall(rb"[ -~]{%d,}" % min_len, data)


def classify_source_type(source_file: str) -> str:
    source = source_file.lower()

    if source.startswith("assets/"):
        return "asset"

    if source.endswith(".dex"):
        return "dex"

    if source.endswith(".so"):
        return "native_library"

    if source.endswith(".xml"):
        return "xml"

    return "apk_member"


def classify_url_confidence(source_file: str, url: str) -> str:
    source = source_file.lower()

    if "libflutter.so" in source:
        return "ignore"

    if source.startswith("assets/flutter_assets/"):
        return "medium"

    if source.endswith(".json"):
        return "medium"

    if source.endswith(".xml"):
        return "medium"

    if source.endswith(".dex"):
        return "low"

    if source.endswith(".so"):
        return "low"

    return "low"


def extract_apk_strings(apk_path: str, min_len: int = 4) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    target_suffixes = (
        ".dex",
        ".xml",
        ".json",
        ".js",
        ".txt",
        ".properties",
        ".so",
    )

    try:
        with zipfile.ZipFile(apk_path, "r") as apk_zip:
            for info in apk_zip.infolist():
                source_file = info.filename

                if not source_file.lower().endswith(target_suffixes):
                    continue

                try:
                    data = apk_zip.read(info)
                except (RuntimeError, OSError, KeyError, zipfile.BadZipFile):
                    continue

                for value in re.findall(rb"[ -~]{%d,}" % min_len, data):
                    decoded = safe_decode(value)

                    if decoded and (source_file, decoded) not in seen:
                        seen.add((source_file, decoded))
                        results.append({"source_file": source_file, "text": decoded})
    except zipfile.BadZipFile:
        for value in byte_strings(apk_path, min_len):
            decoded = safe_decode(value)

            if decoded and (apk_path, decoded) not in seen:
                seen.add((apk_path, decoded))
                results.append({"source_file": apk_path, "text": decoded})

    return sorted(results, key=lambda item: (item["source_file"], item["text"]))


def safe_decode(value: bytes) -> str:
    return value.decode("utf-8", errors="ignore").strip("\x00")


def categorize_permission(
    permission: str,
    permission_categories: Optional[Dict[str, tuple[str, bool]]] = None,
) -> Dict[str, object]:
    categories = permission_categories or PERMISSION_CATEGORIES
    category, sensitive = categories.get(permission, ("other", False))
    return {"name": permission, "category": category, "sensitive": sensitive}


def parse_application(badging: str, apk_path: str) -> Dict[str, object]:
    package_line = next((line for line in badging.splitlines() if line.startswith("package:")), "")
    package_keys = parse_badging_keys(package_line)
    return {
        "apk_path": str(Path(apk_path).resolve()),
        "apk_file_name": Path(apk_path).name,
        "sha256": hashlib.sha256(Path(apk_path).read_bytes()).hexdigest(),
        "file_size_bytes": Path(apk_path).stat().st_size,
        "package_name": package_keys.get("name") or None,
        "version_name": package_keys.get("versionName") or None,
        "version_code": package_keys.get("versionCode") or None,
        "app_label": extract_application_label(badging),
        "min_sdk": extract_badging_value(badging, "sdkVersion"),
        "target_sdk": extract_badging_value(badging, "targetSdkVersion"),
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
                "actions": [],
                "categories": [],
                "is_launcher": name in launchable,
            }
        )
    for name in launchable:
        if not any(item["name"] == name for item in components):
            components.append({"type": "activity", "name": name, "exported": True, "protected_by_permission": False, "permission": "", "deep_links": [], "actions": ["android.intent.action.MAIN"], "categories": ["android.intent.category.LAUNCHER"], "is_launcher": True})
    return components


def extract_deep_links(component: ET.Element) -> List[Dict[str, Optional[str]]]:
    deep_links: List[Dict[str, Optional[str]]] = []

    for intent_filter in component.findall("intent-filter"):
        actions = {
            action.get(android_attr("name"))
            for action in intent_filter.findall("action")
        }

        if "android.intent.action.VIEW" not in actions:
            continue

        for data in intent_filter.findall("data"):
            deep_links.append(
                {
                    "scheme": data.get(android_attr("scheme")),
                    "host": data.get(android_attr("host")),
                    "path": (
                        data.get(android_attr("path"))
                        or data.get(android_attr("pathPrefix"))
                        or data.get(android_attr("pathPattern"))
                    ),
                }
            )

    return deep_links


def extract_intent_filter_info(component: ET.Element) -> Dict[str, object]:
    actions: set[str] = set()
    categories: set[str] = set()

    for intent_filter in component.findall("intent-filter"):
        for action in intent_filter.findall("action"):
            value = action.get(android_attr("name"))
            if value:
                actions.add(value)

        for category in intent_filter.findall("category"):
            value = category.get(android_attr("name"))
            if value:
                categories.add(value)

    return {
        "actions": sorted(actions),
        "categories": sorted(categories),
        "is_launcher": (
            "android.intent.action.MAIN" in actions
            and "android.intent.category.LAUNCHER" in categories
        ),
    }


def parse_manifest_components(manifest_xml: str) -> List[Dict[str, object]]:
    if not manifest_xml.strip():
        return []

    try:
        root = ET.fromstring(manifest_xml)
    except ET.ParseError:
        return []

    application = root.find("application")

    if application is None:
        return []

    components: List[Dict[str, object]] = []
    tag_mapping = {
        "activity": "activity",
        "activity-alias": "activity_alias",
        "service": "service",
        "receiver": "broadcast_receiver",
        "provider": "provider",
    }

    for xml_tag, component_type in tag_mapping.items():
        for element in application.findall(xml_tag):
            name = element.get(android_attr("name"))

            if not name:
                continue

            exported_text = element.get(android_attr("exported"))
            permission = element.get(android_attr("permission"))
            intent_filters = element.findall("intent-filter")

            if exported_text is not None:
                exported = exported_text.lower() == "true"
            else:
                exported = bool(intent_filters)

            intent_info = extract_intent_filter_info(element)

            components.append(
                {
                    "type": component_type,
                    "name": name,
                    "exported": exported,
                    "protected_by_permission": bool(permission),
                    "permission": permission or "",
                    "deep_links": extract_deep_links(element),
                    "actions": intent_info["actions"],
                    "categories": intent_info["categories"],
                    "is_launcher": intent_info["is_launcher"],
                }
            )

    return components


def detect_hints(decoded_strings: List[str], hints: Dict[str, Sequence[str]]) -> Dict[str, List[str]]:
    joined_lower = "\n".join(decoded_strings).lower()
    detected: Dict[str, List[str]] = {}
    for name, needles in hints.items():
        hits = sorted({needle for needle in needles if needle.lower() in joined_lower})
        if hits:
            detected[name] = hits
    return detected


def format_api_evidence(
    detected: Dict[str, List[str]],
    declared_permissions: set[str],
) -> Dict[str, List[Dict[str, object]]]:
    """Attach permission-aware confidence to signature-qualified API hits."""
    permission_map = {
        "location": {"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION"},
        "contacts": {"android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS"},
        "device_identifier": {"android.permission.READ_PHONE_STATE", "android.permission.READ_PHONE_NUMBERS"},
        "camera": {"android.permission.CAMERA"},
        "audio": {"android.permission.RECORD_AUDIO"},
    }
    return {
        category: [
            {
                "category": category,
                "value": value,
                "evidence_type": "class_qualified_string_match",
                "confidence": "medium" if permission_map.get(category, set()) & declared_permissions else "low",
                "permission_declared": bool(permission_map.get(category, set()) & declared_permissions),
            }
            for value in values
        ]
        for category, values in detected.items()
    }


def build_json_report(
    apk_path: str,
    badging: str,
    findings: List[StaticFinding],
    decoded_strings: List[str],
    manifest_status: Dict[str, object],
    component_status: Dict[str, object],
    components: List[Dict[str, object]],
    config: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    config = config or load_static_config()
    permission_categories = configured_permission_categories(config)
    sdk_hints_config, sdk_metadata = configured_sdk_hints(config["sdk_signatures"])
    permissions = [
        categorize_permission(permission, permission_categories)
        for permission in sorted(set(extract_permissions(badging)))
    ]
    declared_permissions = {permission["name"] for permission in permissions}
    sensitive_api_string_hints = format_api_evidence(
        detect_configured_api_hints(decoded_strings, config["sensitive_apis"]),
        declared_permissions,
    )
    network_api_hints = detect_configured_api_hints(decoded_strings, config["network_apis"])
    sdk_hints = detect_hints(decoded_strings, sdk_hints_config)
    report = {
        "schema_version": "1.0",
        "analysis_status": (
            "success"
            if manifest_status["status"] == "success"
            else "partial"
        ),
        "stages": {
            "file_analysis": {
                "status": "success",
            },
            "manifest_badging_analysis": manifest_status,
            "manifest_xml_analysis": component_status,
            "string_analysis": {
                "status": "success",
            },
        },
        "application": parse_application(badging, apk_path),
        "permissions": permissions,
        "components": components,
        "component_summary": summarize_components(components),
        "sensitive_api_string_hints": sensitive_api_string_hints,
        "network_api_hints": network_api_hints,
        "sdk_hints": sdk_hints,
        "sdk_metadata": {name: sdk_metadata[name] for name in sdk_hints},
        "findings": [asdict(finding) for finding in findings],
    }
    report["dynamic_analysis_handoff"] = build_dynamic_analysis_handoff(report)
    return report


def build_dynamic_analysis_handoff(report: Dict[str, object]) -> Dict[str, object]:
    """Build a compact, stable index intended for consumption by dynamic analysis."""

    findings = report.get("findings", [])
    assert isinstance(findings, list)
    domains: Dict[str, set[str]] = {}
    urls: set[str] = set()
    for item in findings:
        if not isinstance(item, dict):
            continue
        signal_type = str(item.get("signal_type", ""))
        value = str(item.get("value", ""))
        if signal_type == "domain" and value:
            domains.setdefault(value.lower().rstrip("."), set()).add(str(item.get("name", "domain")))
        elif signal_type == "url" and value:
            urls.add(value)
            host = urlparse(value).hostname
            if host:
                domains.setdefault(host.lower().rstrip("."), set()).add("embedded_url_candidate")

    permissions = report.get("permissions", [])
    assert isinstance(permissions, list)
    sensitive_categories = {
        str(item["category"])
        for item in permissions
        if isinstance(item, dict) and item.get("sensitive") and item.get("category")
    }
    api_hints = report.get("sensitive_api_string_hints", {})
    if isinstance(api_hints, dict):
        sensitive_categories.update(api_hints)

    application = report.get("application", {})
    sdk_metadata = report.get("sdk_metadata", {})
    return {
        "schema_version": "1.0",
        "package_name": application.get("package_name") if isinstance(application, dict) else None,
        "expected_domains": [
            {"domain": domain, "static_evidence": sorted(evidence)}
            for domain, evidence in sorted(domains.items())
        ],
        "expected_urls": sorted(urls),
        "sensitive_data_categories": sorted(sensitive_categories),
        "sdk_ids": sorted(
            str(item.get("id"))
            for item in sdk_metadata.values()
            if isinstance(item, dict) and item.get("id")
        ) if isinstance(sdk_metadata, dict) else [],
    }


def summarize_components(components: List[Dict[str, object]]) -> Dict[str, Dict[str, int]]:
    summary: Dict[str, Dict[str, int]] = {}
    for item in components:
        key = str(item["type"])
        summary.setdefault(key, {"total": 0, "exported": 0, "unprotected_exported": 0})
        summary[key]["total"] += 1
        if item.get("exported"):
            summary[key]["exported"] += 1
            if (
                not item.get("protected_by_permission")
                and not item.get("is_launcher")
            ):
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
    config_dir: Path | str = CONFIG_DIR,
) -> List[StaticFinding]:
    apk_path = str(Path(apk_path).resolve())

    with static_analysis_stage("input_validation", apk_path):
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")
        if not os.path.isfile(apk_path):
            raise ValueError(f"APK path is not a file: {apk_path}")

    with static_analysis_stage("config_loading", apk_path):
        config = load_static_config(config_dir)
    permission_categories = configured_permission_categories(config)
    sdk_hints, _ = configured_sdk_hints(config["sdk_signatures"])

    with static_analysis_stage("manifest_analysis", apk_path):
        badging, manifest_status = aapt_badging(apk_path)
        manifest_xml, component_status = get_manifest_xml(apk_path)
        components = parse_manifest_components(manifest_xml)
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

    with static_analysis_stage("apk_metadata", apk_path):
        application = parse_application(badging, apk_path)

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
        category = categorize_permission(permission, permission_categories)

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

    if not components:
        components = parse_components(badging)

    for component in components:
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

    with static_analysis_stage("apk_string_extraction", apk_path):
        raw_data = Path(apk_path).read_bytes()
        string_records = extract_apk_strings(apk_path)
    decoded_strings = [record["text"] for record in string_records]
    joined_text = "\n".join(decoded_strings)
    joined_lower = joined_text.lower()
    searchable_data = raw_data + b"\n" + joined_text.encode("utf-8", errors="ignore")

    url_findings: set[tuple[str, str]] = set()
    for record in string_records:
        source_file = record["source_file"]
        source_type = classify_source_type(source_file)
        text = record["text"]

        for match in re.findall(r"https?://[^\s\"'<>]+", text):
            cleaned_url = clean_url_candidate(match)

            if not cleaned_url:
                continue

            confidence = classify_url_confidence(source_file, cleaned_url)

            if confidence == "ignore":
                continue

            key = (cleaned_url, source_file)
            if key in url_findings:
                continue
            url_findings.add(key)

            add(
                "url",
                "embedded_url_candidate",
                cleaned_url,
                (
                    f"source_file={source_file} "
                    f"source_type={source_type} "
                    f"confidence={confidence}"
                ),
            )

    for host in extract_candidate_hosts(decoded_strings):
        add(
            "domain",
            "embedded_host_candidate",
            host,
            "Extracted from APK member strings; low-confidence",
        )

    for raw_domain in sorted(
        set(DOMAIN_RE.findall(searchable_data))
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

    for category, hits in detect_configured_api_hints(
        decoded_strings,
        config["sensitive_apis"],
    ).items():
        add(
            "sensitive_api_string_hint",
            category,
            ";".join(hits),
            "APK strings; evidence_type=class_qualified_string_match",
        )

    for category, hits in detect_configured_api_hints(
        decoded_strings,
        config["network_apis"],
    ).items():
        add(
            "network_api_hint",
            category,
            ";".join(hits),
            "APK strings",
        )

    for sdk_name, hits in detect_hints(
        decoded_strings,
        sdk_hints,
    ).items():
        add(
            "sdk_hint",
            sdk_name,
            ";".join(hits),
            "APK strings",
        )

    output = Path(output_path)
    with static_analysis_stage("csv_report_write", apk_path):
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(STATIC_COLUMNS)
            for finding in findings:
                writer.writerow(finding.row())

    if json_output_path:
        json_output = Path(json_output_path)
        with static_analysis_stage("json_report_write", apk_path):
            json_output.parent.mkdir(parents=True, exist_ok=True)
            report = build_json_report(
                apk_path,
                badging,
                findings,
                decoded_strings,
                manifest_status,
                component_status,
                components,
                config,
            )
            json_output.write_text(
                json.dumps(report, ensure_ascii=False, indent=2),
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
    parser.add_argument("--config-dir", default=str(CONFIG_DIR), help="Directory containing static-analysis YAML rules.")
    return parser.parse_args() 

def main() -> int:
    args = parse_args()
    try:
        analyze_static(args.apk, args.output, args.json_output, args.config_dir)
    except StaticAnalysisStageError as exc:
        print(f"[Static][ERROR] stage={exc.stage} apk={exc.apk_path}", file=sys.stderr)
        print(f"[Static][ERROR] cause={type(exc.cause).__name__}: {exc.cause}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
