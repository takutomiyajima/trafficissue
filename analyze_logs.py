from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence


RESULT_COLUMNS = [
    "event_id",
    "ui_timestamp",
    "screen",
    "action",
    "element_text",
    "traffic_timestamp",
    "time_delta",
    "observability_status",
    "domain",
    "scheme",
    "method",
    "url",
    "status_code",
    "risk",
    "risk_category",
    "reason",
]


DEFAULT_UI_PATH = "logs/ui_events.csv"
DEFAULT_TRAFFIC_PATH = "logs/traffic_logs.csv"
DEFAULT_OUTPUT_PATH = "logs/risk_results.csv"
DEFAULT_WINDOW_SECONDS = 5.0
DEFAULT_ALLOWED_DOMAINS = ("example.com", "api.example.com")
LOCATION_KEYWORDS = ("location", "位置", "現在地", "地図", "map", "maps", "gps")
MAPS_DOMAINS = ("maps.googleapis.com",)
SYSTEM_CONNECTIVITY_CHECK_DOMAINS = (
    "connectivitycheck.gstatic.com",
    "www.google.com",
    "play.googleapis.com",
)
SYSTEM_CONNECTIVITY_CHECK_PATHS = ("/generate_204", "/gen_204")
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


@dataclass(frozen=True)
class RiskDecision:
    risk: str
    risk_category: str
    reason: str


def _clean(value: object) -> str:
    """Return a normalized string for CSV cells that may be NaN/None."""
    if value is None or value != value:
        return ""
    return str(value).strip()


def _is_allowed_domain(domain: str, allowed_domains: Sequence[str]) -> bool:
    normalized_domain = domain.lower().rstrip(".")
    for allowed in allowed_domains:
        normalized_allowed = allowed.lower().strip().rstrip(".")
        if not normalized_allowed:
            continue
        if normalized_domain == normalized_allowed or normalized_domain.endswith(f".{normalized_allowed}"):
            return True
    return False


def _contains_any(value: str, keywords: Iterable[str]) -> bool:
    normalized = value.lower()
    return any(keyword.lower() in normalized for keyword in keywords)


def is_system_connectivity_probe(scheme: str, domain: str, url: str, status_code: object = "") -> bool:
    """Return True for Android/Google connectivity checks that are not app-initiated traffic."""
    from urllib.parse import urlparse

    normalized_scheme = scheme.lower().strip()
    normalized_domain = domain.lower().strip().rstrip(".")
    if normalized_scheme != "http" or not _is_allowed_domain(normalized_domain, SYSTEM_CONNECTIVITY_CHECK_DOMAINS):
        return False

    path = urlparse(url).path if url else ""
    if path not in SYSTEM_CONNECTIVITY_CHECK_PATHS:
        return False

    normalized_status = _clean(status_code)
    return normalized_status in {"", "0", "204", "204.0"}


def classify_risk(
    scheme: str,
    domain: str,
    ui_text: str,
    allowed_domains: Sequence[str] = DEFAULT_ALLOWED_DOMAINS,
) -> RiskDecision:
    """Classify traffic risk using UI context, protocol, and destination domain."""
    normalized_scheme = scheme.lower()
    normalized_domain = domain.lower()
    normalized_ui_text = ui_text.lower()

    if not normalized_scheme or not normalized_domain:
        return RiskDecision(
            "Low",
            "判定保留",
            "通信先ドメインまたは通信方式を取得できなかったため、リスク判定は保留扱いです。",
        )

    if normalized_scheme == "http":
        return RiskDecision(
            "High",
            "平文HTTP通信",
            "UI操作後に暗号化されていないHTTP通信を検知しました（盗聴・改ざんリスク）。",
        )

    if _contains_any(normalized_domain, TRACKER_KEYWORDS):
        return RiskDecision(
            "High",
            "広告・解析トラッカー",
            "UI操作後に広告・解析・トラッカー系ドメインへの通信を検知しました。",
        )

    if _contains_any(normalized_domain, MAPS_DOMAINS) and _contains_any(normalized_ui_text, LOCATION_KEYWORDS):
        return RiskDecision(
            "High",
            "位置情報関連通信",
            "位置情報関連のUI操作後に地図APIへの通信を検知しました。位置情報送信の可能性があります。",
        )

    if normalized_scheme == "https":
        if _is_allowed_domain(normalized_domain, allowed_domains):
            return RiskDecision(
                "Low",
                "First-party HTTPS",
                "allowlist内のFirst-party HTTPS通信として扱いました。",
            )
        return RiskDecision(
            "Middle",
            "外部HTTPS通信",
            "allowlist外のHTTPS通信を検知しました。HTTPSでも外部送信の可能性があるため注意が必要です。",
        )

    return RiskDecision(
        "Middle",
        "未分類プロトコル",
        f"未分類の通信方式（{scheme}）を検知しました。追加確認が必要です。",
    )


def _read_log_csv(path: str, columns: Sequence[str]):
    """Read a tool-generated CSV log and return a dataframe with stable columns.

    mitmproxy can be interrupted before it writes the traffic header, and some CSV
    tools add whitespace or a UTF-8 BOM to column names.  Normalize those cases so
    later timestamp correlation never raises a KeyError for a missing expected
    column.
    """
    import pandas as pd
    from pandas.errors import EmptyDataError

    try:
        df = pd.read_csv(path)
    except EmptyDataError:
        df = pd.DataFrame(columns=columns)

    df = df.copy()
    df.columns = [_clean(column).lstrip("\ufeff") for column in df.columns]
    return _ensure_columns(df, columns)


def _ensure_columns(df, columns: Sequence[str]):
    for column in columns:
        if column not in df.columns:
            df[column] = ""
    return df.reindex(columns=list(columns) + [column for column in df.columns if column not in columns])


def analyze(
    ui_path: str = DEFAULT_UI_PATH,
    traffic_path: str = DEFAULT_TRAFFIC_PATH,
    output_path: str = DEFAULT_OUTPUT_PATH,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
    allowed_domains: Optional[Sequence[str]] = None,
    include_system_probes: bool = False,
):
    import pandas as pd

    allowed_domains = tuple(allowed_domains or DEFAULT_ALLOWED_DOMAINS)

    if not os.path.exists(ui_path) or not os.path.exists(traffic_path):
        raise FileNotFoundError("Logs not found. Please run capture and runner first.")

    ui_df = _read_log_csv(ui_path, ["event_id", "timestamp", "screen", "action", "element_text"])
    traffic_df = _read_log_csv(traffic_path, ["timestamp", "scheme", "domain", "method", "url", "status_code"])

    ui_df["timestamp"] = pd.to_numeric(ui_df["timestamp"], errors="coerce")
    traffic_df["timestamp"] = pd.to_numeric(traffic_df["timestamp"], errors="coerce")
    traffic_df = traffic_df.dropna(subset=["timestamp"]).copy()
    traffic_df = traffic_df.drop_duplicates(subset=["timestamp", "scheme", "domain", "method", "url", "status_code"])

    if not include_system_probes:
        system_probe_mask = traffic_df.apply(
            lambda row: is_system_connectivity_probe(
                _clean(row.get("scheme")),
                _clean(row.get("domain")),
                _clean(row.get("url")),
                row.get("status_code"),
            ),
            axis=1,
        )
        traffic_df = traffic_df[~system_probe_mask].copy()

    results: List[dict] = []

    for _, ui_row in ui_df.dropna(subset=["timestamp"]).iterrows():
        ui_time = float(ui_row["timestamp"])
        event_id = _clean(ui_row.get("event_id"))
        element_text = _clean(ui_row.get("element_text"))
        screen = _clean(ui_row.get("screen"))
        action = _clean(ui_row.get("action")) or "tap"

        matched_traffic = traffic_df[
            (traffic_df["timestamp"] >= ui_time)
            & (traffic_df["timestamp"] <= ui_time + window_seconds)
        ].sort_values("timestamp")

        if matched_traffic.empty:
            results.append(
                {
                    "event_id": event_id,
                    "ui_timestamp": ui_time,
                    "screen": screen,
                    "action": action,
                    "element_text": element_text,
                    "traffic_timestamp": "",
                    "time_delta": "",
                    "observability_status": "none",
                    "domain": "",
                    "scheme": "",
                    "method": "",
                    "url": "",
                    "status_code": "",
                    "risk": "Low",
                    "risk_category": "通信なし",
                    "reason": f"操作後{window_seconds:g}秒以内に通信は観測されませんでした。",
                }
            )
            continue

        for _, traffic_row in matched_traffic.iterrows():
            traffic_time = float(traffic_row["timestamp"])
            delta = traffic_time - ui_time
            scheme = _clean(traffic_row.get("scheme"))
            domain = _clean(traffic_row.get("domain"))
            decision = classify_risk(scheme, domain, element_text, allowed_domains)

            results.append(
                {
                    "event_id": event_id,
                    "ui_timestamp": ui_time,
                    "screen": screen,
                    "action": action,
                    "element_text": element_text,
                    "traffic_timestamp": traffic_time,
                    "time_delta": round(delta, 3),
                    "observability_status": "observed",
                    "domain": domain,
                    "scheme": scheme,
                    "method": _clean(traffic_row.get("method")),
                    "url": _clean(traffic_row.get("url")),
                    "status_code": _clean(traffic_row.get("status_code")),
                    "risk": decision.risk,
                    "risk_category": decision.risk_category,
                    "reason": decision.reason,
                }
            )

    res_df = pd.DataFrame(results, columns=RESULT_COLUMNS)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    res_df.to_csv(output_path, index=False)
    print(f"[Analyzer] Analysis complete. Saved to {output_path}")
    return res_df


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Correlate Android UI events with traffic logs and classify risk.")
    parser.add_argument("--ui-log", default=DEFAULT_UI_PATH, help="Path to ui_events.csv.")
    parser.add_argument("--traffic-log", default=DEFAULT_TRAFFIC_PATH, help="Path to traffic_logs.csv.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT_PATH, help="Path to write risk_results.csv.")
    parser.add_argument("--window", type=float, default=DEFAULT_WINDOW_SECONDS, help="Seconds after each UI event to correlate traffic.")
    parser.add_argument(
        "--allowed-domain",
        action="append",
        dest="allowed_domains",
        help="First-party/allowlisted domain. Can be specified multiple times.",
    )
    parser.add_argument(
        "--include-system-probes",
        action="store_true",
        help="Include Android/Google connectivity probe traffic such as generate_204 in correlation results.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    try:
        analyze(
            ui_path=args.ui_log,
            traffic_path=args.traffic_log,
            output_path=args.output,
            window_seconds=args.window,
            allowed_domains=args.allowed_domains,
            include_system_probes=args.include_system_probes,
        )
    except FileNotFoundError as exc:
        print(f"[Error] {exc}")
