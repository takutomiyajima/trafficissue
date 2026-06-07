from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Sequence
from urllib.parse import parse_qsl, unquote, urlparse


TRACKER_KEYWORDS = (
    "doubleclick.net",
    "googlesyndication.com",
    "google-analytics.com",
    "firebase-settings.crashlytics.com",
    "app-measurement.com",
    "facebook.com",
    "adjust.com",
    "appsflyer.com",
)
SENSITIVE_KEY_RULES = (
    (("email", "mail", "e-mail"), "email"),
    (("phone", "tel", "mobile", "msisdn"), "phone"),
    (("lat", "latitude", "lon", "lng", "longitude", "location", "gps"), "location"),
    (("imei", "imsi", "android_id", "device_id", "advertising_id", "adid", "gaid", "idfa"), "device_id"),
    (("token", "access_token", "refresh_token", "auth", "authorization", "session", "sid"), "token"),
)
SENSITIVE_VALUE_PATTERNS = (
    (re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE), "email"),
    (re.compile(r"(?:\+?\d[\d ._()-]{8,}\d)"), "phone"),
)
SEVERITY_ORDER = {"Unknown": -1, "Low": 0, "Medium": 1, "High": 2}


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    severity: str
    category: str
    reason: str
    signal: str
    data_categories: Sequence[str] = ()


def _clean(value: object) -> str:
    if value is None or value != value:
        return ""
    return str(value).strip()


def is_allowed_domain(domain: str, allowed_domains: Sequence[str]) -> bool:
    normalized_domain = domain.lower().rstrip(".")
    for allowed in allowed_domains:
        normalized_allowed = allowed.lower().strip().rstrip(".")
        if not normalized_allowed:
            continue
        if normalized_domain == normalized_allowed or normalized_domain.endswith(f".{normalized_allowed}"):
            return True
    return False


def destination_party(domain: str, allowed_domains: Sequence[str]) -> str:
    if not domain:
        return "unknown"
    return "first-party" if is_allowed_domain(domain, allowed_domains) else "third-party"


def contains_tracker_domain(domain: str) -> bool:
    normalized_domain = domain.lower()
    return any(keyword in normalized_domain for keyword in TRACKER_KEYWORDS)


def _matches_sensitive_query_key(normalized_key: str, keyword: str) -> bool:
    if "_" in keyword:
        return keyword in normalized_key
    key_tokens = [token for token in re.split(r"[^a-z0-9]+", normalized_key) if token]
    if len(keyword) <= 3:
        return keyword in key_tokens
    return normalized_key == keyword or keyword in key_tokens


def detect_sensitive_url_fields(url: str) -> List[str]:
    """Detect only categories of privacy-sensitive URL keys/values, not raw values."""
    if not url:
        return []

    parsed = urlparse(url)
    detected: List[str] = []

    def add(label: str) -> None:
        if label not in detected:
            detected.append(label)

    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        normalized_key = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
        for keywords, label in SENSITIVE_KEY_RULES:
            if any(_matches_sensitive_query_key(normalized_key, keyword) for keyword in keywords):
                add(label)
        decoded_value = unquote(value)
        for pattern, label in SENSITIVE_VALUE_PATTERNS:
            if pattern.search(decoded_value):
                add(label)

    decoded_path = unquote(parsed.path)
    for pattern, label in SENSITIVE_VALUE_PATTERNS:
        if pattern.search(decoded_path):
            add(label)

    return detected


def evaluate_traffic_risk(
    scheme: str,
    domain: str,
    url: str,
    allowed_domains: Sequence[str],
    time_delta: object = "",
    event_id: str = "",
    startup_window_seconds: float = 3.0,
    status_code: object = "",
    method: str = "",
    request_size: object = "",
    error: object = "",
) -> RuleResult:
    """Return the highest-priority rule hit for one traffic record.

    The rules are intentionally small and auditable: unsafe transport, sensitive
    data in URLs, known tracker domains, third-party destinations, uploads to
    third parties, and failed/blocked connections. Raw sensitive values are not
    copied into the result reason.
    """
    normalized_scheme = _clean(scheme).lower().rstrip(":/")
    normalized_domain = _clean(domain).lower()
    normalized_url = _clean(url)
    normalized_method = _clean(method).upper()
    normalized_error = _clean(error)
    candidates: List[RuleResult] = []

    sensitive_categories = detect_sensitive_url_fields(normalized_url)
    if sensitive_categories:
        candidates.append(
            RuleResult(
                rule_id="sensitive_key",
                severity="High",
                category="個人情報らしいキー",
                reason="URLに個人情報または識別子らしいキー/値が含まれています。",
                signal="url_query_or_path",
                data_categories=tuple(sensitive_categories),
            )
        )

    if normalized_scheme == "http":
        candidates.append(
            RuleResult(
                rule_id="cleartext_http",
                severity="High",
                category="HTTP平文通信",
                reason="平文HTTP通信が行われています。",
                signal="scheme=http",
            )
        )

    if contains_tracker_domain(normalized_domain):
        candidates.append(
            RuleResult(
                rule_id="tracker_domain",
                severity="Medium",
                category="広告・解析系通信",
                reason="広告・解析系ドメインへの通信です。",
                signal="tracker_domain",
            )
        )

    try:
        numeric_request_size = int(float(_clean(request_size) or 0))
    except (TypeError, ValueError):
        numeric_request_size = 0
    if (
        normalized_method in {"POST", "PUT", "PATCH"}
        and numeric_request_size > 0
        and normalized_domain
        and not is_allowed_domain(normalized_domain, allowed_domains)
    ):
        candidates.append(
            RuleResult(
                rule_id="third_party_upload",
                severity="Medium",
                category="外部送信",
                reason="許可ドメイン外へリクエスト本文を送信しています。",
                signal="non_allowlisted_body_upload",
            )
        )

    if normalized_error:
        candidates.append(
            RuleResult(
                rule_id="connection_error",
                severity="Medium",
                category="通信エラー",
                reason="通信が失敗または遮断されています。",
                signal="mitmproxy_error",
            )
        )

    try:
        numeric_status = int(float(_clean(status_code)))
    except (TypeError, ValueError):
        numeric_status = 0
    if numeric_status >= 500:
        candidates.append(
            RuleResult(
                rule_id="server_error",
                severity="Medium",
                category="サーバーエラー",
                reason="通信先が5xxエラーを返しています。",
                signal="status_code>=500",
            )
        )

    try:
        delta = float(time_delta)
    except (TypeError, ValueError):
        delta = None
    if event_id in {"E000", "E001"} and delta is not None and 0 <= delta <= startup_window_seconds:
        candidates.append(
            RuleResult(
                rule_id="startup_transmission",
                severity="Medium",
                category="起動直後通信",
                reason="アプリ起動直後または最初の操作直後に通信が発生しています。",
                signal=f"time_delta<={startup_window_seconds:g}s",
            )
        )

    if normalized_scheme == "https" and normalized_domain:
        if is_allowed_domain(normalized_domain, allowed_domains):
            candidates.append(
                RuleResult(
                    rule_id="first_party_https",
                    severity="Low",
                    category="First-party HTTPS",
                    reason="許可ドメイン内のHTTPS通信です。",
                    signal="allowlisted_https",
                )
            )
        else:
            candidates.append(
                RuleResult(
                    rule_id="third_party_domain",
                    severity="Medium",
                    category="第三者ドメイン通信",
                    reason="許可ドメイン外へのHTTPS通信です。",
                    signal="non_allowlisted_https",
                )
            )

    if candidates:
        return max(candidates, key=lambda result: SEVERITY_ORDER[result.severity])

    if not normalized_scheme or not normalized_domain:
        return RuleResult(
            rule_id="unreadable_traffic",
            severity="Unknown",
            category="判定不能通信",
            reason="通信は観測されましたが、通信方式または通信先ドメインを取得できなかったためリスク判定できません。",
            signal="missing_scheme_or_domain",
        )

    return RuleResult(
        rule_id="unclassified",
        severity="Low",
        category="未分類通信",
        reason="上位リスクルールには一致しませんでした。",
        signal="no_rule_hit",
    )
