from __future__ import annotations

import argparse
import os
from typing import List, Optional, Sequence

from risk_rules import (
    RuleResult,
    destination_party,
    detect_sensitive_url_fields,
    evaluate_traffic_risk,
    is_allowed_domain,
)


RESULT_COLUMNS = [
    "event_id",
    "app_package",
    "ui_timestamp",
    "screen",
    "action",
    "element_text",
    "traffic_timestamp",
    "time_delta",
    "observability_status",
    "domain",
    "destination_party",
    "scheme",
    "method",
    "url",
    "status_code",
    "content_type",
    "request_size",
    "response_size",
    "risk",
    "risk_category",
    "risk_rule",
    "risk_signal",
    "data_categories",
    "reason",
]


DEFAULT_UI_PATH = "logs/ui_events.csv"
DEFAULT_TRAFFIC_PATH = "logs/traffic_logs.csv"
DEFAULT_OUTPUT_PATH = "logs/risk_results.csv"
DEFAULT_WINDOW_SECONDS = 5.0
DEFAULT_ALLOWED_DOMAINS = ("example.com", "api.example.com")
SYSTEM_CONNECTIVITY_CHECK_DOMAINS = (
    "connectivitycheck.gstatic.com",
    "www.google.com",
    "play.googleapis.com",
)
SYSTEM_CONNECTIVITY_CHECK_PATHS = ("/generate_204", "/gen_204")
TRAFFIC_COLUMNS = [
    "timestamp",
    "scheme",
    "domain",
    "method",
    "url",
    "status_code",
    "content_type",
    "request_size",
    "response_size",
]
UI_COLUMNS = ["event_id", "timestamp", "screen", "action", "element_text"]


def _clean(value: object) -> str:
    """Return a normalized string for CSV cells that may be NaN/None."""
    if value is None or value != value:
        return ""
    return str(value).strip()


def extract_app_package(screen: str) -> str:
    """Extract package-like prefix from screen values such as com.example/.MainActivity."""
    screen = _clean(screen)
    return screen.split("/", 1)[0] if "/" in screen else ""


def is_system_connectivity_probe(scheme: str, domain: str, url: str, status_code: object = "") -> bool:
    """Return True for Android/Google connectivity checks that are not app-initiated traffic."""
    from urllib.parse import urlparse

    normalized_scheme = scheme.lower().strip()
    normalized_domain = domain.lower().strip().rstrip(".")
    if normalized_scheme != "http" or not is_allowed_domain(normalized_domain, SYSTEM_CONNECTIVITY_CHECK_DOMAINS):
        return False

    path = urlparse(url).path if url else ""
    if path not in SYSTEM_CONNECTIVITY_CHECK_PATHS:
        return False

    normalized_status = _clean(status_code)
    return normalized_status in {"", "0", "204", "204.0"}


def classify_risk(
    scheme: str,
    domain: str,
    ui_text: str = "",
    allowed_domains: Sequence[str] = DEFAULT_ALLOWED_DOMAINS,
    url: str = "",
    time_delta: object = "",
    event_id: str = "",
) -> RuleResult:
    """Classify privacy risk with the focused MVP rule set."""
    return evaluate_traffic_risk(
        scheme=scheme,
        domain=domain,
        url=url,
        allowed_domains=allowed_domains,
        time_delta=time_delta,
        event_id=event_id,
    )


def _read_log_csv(path: str, columns: Sequence[str]):
    """Read a tool-generated CSV log and return a dataframe with stable columns."""
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

    ui_df = _read_log_csv(ui_path, UI_COLUMNS)
    traffic_df = _read_log_csv(traffic_path, TRAFFIC_COLUMNS)

    ui_df["timestamp"] = pd.to_numeric(ui_df["timestamp"], errors="coerce")
    traffic_df["timestamp"] = pd.to_numeric(traffic_df["timestamp"], errors="coerce")
    traffic_df = traffic_df.dropna(subset=["timestamp"]).copy()
    traffic_df = traffic_df.drop_duplicates(subset=TRAFFIC_COLUMNS)

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
        app_package = extract_app_package(screen)

        matched_traffic = traffic_df[
            (traffic_df["timestamp"] >= ui_time)
            & (traffic_df["timestamp"] <= ui_time + window_seconds)
        ].sort_values("timestamp")

        if matched_traffic.empty:
            results.append(
                {
                    "event_id": event_id,
                    "app_package": app_package,
                    "ui_timestamp": ui_time,
                    "screen": screen,
                    "action": action,
                    "element_text": element_text,
                    "traffic_timestamp": "",
                    "time_delta": "",
                    "observability_status": "none",
                    "domain": "",
                    "destination_party": "none",
                    "scheme": "",
                    "method": "",
                    "url": "",
                    "status_code": "",
                    "content_type": "",
                    "request_size": "",
                    "response_size": "",
                    "risk": "Low",
                    "risk_category": "通信なし",
                    "risk_rule": "no_traffic",
                    "risk_signal": "no_request_in_window",
                    "data_categories": "",
                    "reason": f"操作後{window_seconds:g}秒以内に通信は観測されませんでした。",
                }
            )
            continue

        for _, traffic_row in matched_traffic.iterrows():
            traffic_time = float(traffic_row["timestamp"])
            delta = round(traffic_time - ui_time, 3)
            scheme = _clean(traffic_row.get("scheme"))
            domain = _clean(traffic_row.get("domain"))
            url = _clean(traffic_row.get("url"))
            decision = classify_risk(
                scheme=scheme,
                domain=domain,
                ui_text=element_text,
                allowed_domains=allowed_domains,
                url=url,
                time_delta=delta,
                event_id=event_id,
            )

            results.append(
                {
                    "event_id": event_id,
                    "app_package": app_package,
                    "ui_timestamp": ui_time,
                    "screen": screen,
                    "action": action,
                    "element_text": element_text,
                    "traffic_timestamp": traffic_time,
                    "time_delta": delta,
                    "observability_status": "observed",
                    "domain": domain,
                    "destination_party": destination_party(domain, allowed_domains),
                    "scheme": scheme,
                    "method": _clean(traffic_row.get("method")),
                    "url": url,
                    "status_code": _clean(traffic_row.get("status_code")),
                    "content_type": _clean(traffic_row.get("content_type")),
                    "request_size": _clean(traffic_row.get("request_size")),
                    "response_size": _clean(traffic_row.get("response_size")),
                    "risk": decision.severity,
                    "risk_category": decision.category,
                    "risk_rule": decision.rule_id,
                    "risk_signal": decision.signal,
                    "data_categories": ";".join(decision.data_categories),
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
