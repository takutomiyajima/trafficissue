from __future__ import annotations

import argparse
import os
from typing import List, Optional, Sequence
from urllib.parse import urlparse

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
    "metadata_source",
    "destination_ip",
    "destination_port",
    "protocol",
    "bytes_sent",
    "bytes_received",
    "domain",
    "destination_party",
    "scheme",
    "method",
    "url",
    "status_code",
    "content_type",
    "request_size",
    "response_size",
    "response_timestamp",
    "duration_ms",
    "error",
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
DEFAULT_METADATA_PATH = "logs/pcap_metadata.csv"
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
    "response_timestamp",
    "duration_ms",
    "error",
]
UI_COLUMNS = ["event_id", "timestamp", "screen", "action", "element_text"]

METADATA_COLUMNS = [
    "timestamp",
    "package",
    "destination_host",
    "destination_ip",
    "destination_port",
    "protocol",
    "bytes_sent",
    "bytes_received",
    "source",
]

METADATA_ONLY_CATEGORY = "通信メタデータのみ"
METADATA_ONLY_REASON = "VPN/pcap由来の通信メタデータは観測されましたが、HTTP本文は読めません。"


def _clean(value: object) -> str:
    """Return a normalized string for CSV cells that may be NaN/None."""
    if value is None or value != value:
        return ""
    return str(value).strip()


def extract_app_package(screen: str) -> str:
    """Extract package-like prefix from screen values such as com.example/.MainActivity."""
    screen = _clean(screen)
    return screen.split("/", 1)[0] if "/" in screen else ""


def _derive_scheme_domain(scheme: str, domain: str, url: str) -> tuple[str, str]:
    """Fill missing scheme/domain from a parseable URL before applying risk rules."""
    normalized_scheme = _clean(scheme).lower().rstrip(":/")
    normalized_domain = _clean(domain).lower().rstrip(".")
    normalized_url = _clean(url)

    if normalized_url and (not normalized_scheme or not normalized_domain):
        parsed = urlparse(normalized_url)
        if not normalized_scheme and parsed.scheme:
            normalized_scheme = parsed.scheme.lower()
        if not normalized_domain and parsed.hostname:
            normalized_domain = parsed.hostname.lower().rstrip(".")

    return normalized_scheme, normalized_domain


def observability_status_for_decision(decision: RuleResult) -> str:
    """Return a status that separates readable traffic from traffic with missing metadata."""
    if decision.rule_id == "unreadable_traffic":
        return "unreadable_tls"
    if decision.rule_id == "metadata_only":
        return "metadata_only"
    return "observed"


def no_traffic_status(traffic_log_had_rows: bool, metadata_log_had_rows: bool) -> str:
    """Classify an unmatched UI event without turning non-observation into Low risk."""
    if traffic_log_had_rows or metadata_log_had_rows:
        return "not_observed"
    return "capture_failed"


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
    status_code: object = "",
    method: str = "",
    request_size: object = "",
    error: object = "",
) -> RuleResult:
    """Classify privacy risk with the focused MVP rule set."""
    return evaluate_traffic_risk(
        scheme=scheme,
        domain=domain,
        url=url,
        allowed_domains=allowed_domains,
        time_delta=time_delta,
        event_id=event_id,
        status_code=status_code,
        method=method,
        request_size=request_size,
        error=error,
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


def _normalize_metadata_columns(df):
    """Accept simple PCAPdroid/VPN CSV aliases and normalize them to METADATA_COLUMNS."""
    aliases = {
        "time": "timestamp",
        "ts": "timestamp",
        "app": "package",
        "uid_name": "package",
        "host": "destination_host",
        "hostname": "destination_host",
        "sni": "destination_host",
        "dst_host": "destination_host",
        "server_name": "destination_host",
        "remote_host": "destination_host",
        "ip": "destination_ip",
        "dst_ip": "destination_ip",
        "remote_ip": "destination_ip",
        "dest_ip": "destination_ip",
        "destination_address": "destination_ip",
        "port": "destination_port",
        "dst_port": "destination_port",
        "remote_port": "destination_port",
        "l4_proto": "protocol",
        "sent_bytes": "bytes_sent",
        "rcvd_bytes": "bytes_received",
        "received_bytes": "bytes_received",
        "recv_bytes": "bytes_received",
        "download_bytes": "bytes_received",
    }
    rename_map = {}
    for column in df.columns:
        normalized = _clean(column).lower().replace(" ", "_")
        if normalized in aliases and aliases[normalized] not in df.columns:
            rename_map[column] = aliases[normalized]
    return df.rename(columns=rename_map)



def _empty_metadata_fields() -> dict:
    return {
        "metadata_source": "mitmproxy",
        "destination_ip": "",
        "destination_port": "",
        "protocol": "",
        "bytes_sent": "",
        "bytes_received": "",
    }



def metadata_decision_for_row(domain: str, destination_ip: str, allowed_domains: Sequence[str]) -> RuleResult:
    """Classify VPN/pcap rows as observable metadata without pretending HTTP body was readable."""
    if domain:
        severity = "Low" if is_allowed_domain(domain, allowed_domains) else "Medium"
        party = destination_party(domain, allowed_domains)
        reason = f"{METADATA_ONLY_REASON} 通信先ドメインは{party}として扱います。"
    elif destination_ip:
        severity = "Unknown"
        reason = f"{METADATA_ONLY_REASON} ドメイン名は取れず、宛先IPのみ観測されました。"
    else:
        severity = "Unknown"
        reason = f"{METADATA_ONLY_REASON} 通信先が不完全なためリスク判定は保留します。"

    return RuleResult(
        rule_id="metadata_only",
        severity=severity,
        category=METADATA_ONLY_CATEGORY,
        reason=reason,
        signal="pcap_metadata",
    )


def build_result_for_metadata_row(
    metadata_row,
    allowed_domains: Sequence[str],
    event_id: str,
    ui_time: float | str = "",
    app_package: str = "",
    screen: str = "",
    action: str = "",
    element_text: str = "",
) -> dict:
    """Build a result row for VPN/pcap metadata correlated to a UI event."""
    traffic_time = float(metadata_row["timestamp"])
    delta = round(traffic_time - float(ui_time), 3) if _clean(ui_time) else ""
    domain = _clean(metadata_row.get("destination_host")).lower().rstrip(".")
    destination_ip = _clean(metadata_row.get("destination_ip"))
    decision = metadata_decision_for_row(domain, destination_ip, allowed_domains)
    return {
        "event_id": event_id,
        "app_package": app_package,
        "ui_timestamp": ui_time,
        "screen": screen,
        "action": action,
        "element_text": element_text,
        "traffic_timestamp": traffic_time,
        "time_delta": delta,
        "observability_status": observability_status_for_decision(decision),
        "metadata_source": _clean(metadata_row.get("source")) or "pcap",
        "destination_ip": destination_ip,
        "destination_port": _clean(metadata_row.get("destination_port")),
        "protocol": _clean(metadata_row.get("protocol")),
        "bytes_sent": _clean(metadata_row.get("bytes_sent")),
        "bytes_received": _clean(metadata_row.get("bytes_received")),
        "domain": domain,
        "destination_party": destination_party(domain, allowed_domains),
        "scheme": "",
        "method": "",
        "url": "",
        "status_code": "",
        "content_type": "",
        "request_size": "",
        "response_size": "",
        "response_timestamp": "",
        "duration_ms": "",
        "error": "",
        "risk": decision.severity,
        "risk_category": decision.category,
        "risk_rule": decision.rule_id,
        "risk_signal": decision.signal,
        "data_categories": ";".join(decision.data_categories),
        "reason": decision.reason,
    }


def build_result_for_traffic_row(traffic_row, allowed_domains: Sequence[str], event_id: str = "") -> dict:
    """Classify a single traffic row without requiring UI automation metadata."""
    traffic_timestamp = traffic_row.get("timestamp")
    traffic_time = float(traffic_timestamp) if _clean(traffic_timestamp) else ""
    url = _clean(traffic_row.get("url"))
    scheme, domain = _derive_scheme_domain(traffic_row.get("scheme"), traffic_row.get("domain"), url)
    decision = classify_risk(
        scheme=scheme,
        domain=domain,
        allowed_domains=allowed_domains,
        url=url,
        event_id=event_id,
        status_code=traffic_row.get("status_code"),
        method=traffic_row.get("method"),
        request_size=traffic_row.get("request_size"),
        error=traffic_row.get("error"),
    )
    return {
        "event_id": event_id,
        "app_package": "",
        "ui_timestamp": "",
        "screen": "",
        "action": "",
        "element_text": "",
        "traffic_timestamp": traffic_time,
        "time_delta": "",
        "observability_status": observability_status_for_decision(decision),
        **_empty_metadata_fields(),
        "domain": domain,
        "destination_party": destination_party(domain, allowed_domains),
        "scheme": scheme,
        "method": _clean(traffic_row.get("method")),
        "url": url,
        "status_code": _clean(traffic_row.get("status_code")),
        "content_type": _clean(traffic_row.get("content_type")),
        "request_size": _clean(traffic_row.get("request_size")),
        "response_size": _clean(traffic_row.get("response_size")),
        "response_timestamp": _clean(traffic_row.get("response_timestamp")),
        "duration_ms": _clean(traffic_row.get("duration_ms")),
        "error": _clean(traffic_row.get("error")),
        "risk": decision.severity,
        "risk_category": decision.category,
        "risk_rule": decision.rule_id,
        "risk_signal": decision.signal,
        "data_categories": ";".join(decision.data_categories),
        "reason": decision.reason,
    }

def analyze(
    ui_path: str = DEFAULT_UI_PATH,
    traffic_path: str = DEFAULT_TRAFFIC_PATH,
    output_path: str = DEFAULT_OUTPUT_PATH,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
    allowed_domains: Optional[Sequence[str]] = None,
    include_system_probes: bool = False,
    target_package: str = "",
    metadata_path: str = "",
):
    import pandas as pd

    allowed_domains = tuple(allowed_domains or DEFAULT_ALLOWED_DOMAINS)

    if not os.path.exists(traffic_path):
        raise FileNotFoundError("Traffic log not found. Please run capture first.")

    ui_df = _read_log_csv(ui_path, UI_COLUMNS) if os.path.exists(ui_path) else pd.DataFrame(columns=UI_COLUMNS)
    traffic_df = _read_log_csv(traffic_path, TRAFFIC_COLUMNS)
    metadata_df = (
        _ensure_columns(_normalize_metadata_columns(_read_log_csv(metadata_path, ())), METADATA_COLUMNS)
        if metadata_path and os.path.exists(metadata_path)
        else pd.DataFrame(columns=METADATA_COLUMNS)
    )

    ui_df["timestamp"] = pd.to_numeric(ui_df["timestamp"], errors="coerce")
    traffic_df["timestamp"] = pd.to_numeric(traffic_df["timestamp"], errors="coerce")
    metadata_df["timestamp"] = pd.to_numeric(metadata_df["timestamp"], errors="coerce")
    traffic_df = traffic_df.dropna(subset=["timestamp"]).copy()
    metadata_df = metadata_df.dropna(subset=["timestamp"]).copy()
    traffic_log_had_rows = not traffic_df.empty
    metadata_log_had_rows = not metadata_df.empty
    traffic_df = traffic_df.drop_duplicates(subset=TRAFFIC_COLUMNS)
    metadata_df = metadata_df.drop_duplicates(subset=METADATA_COLUMNS)

    if not include_system_probes and not traffic_df.empty:
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
        traffic_df = _ensure_columns(traffic_df, TRAFFIC_COLUMNS)

    target_package = _clean(target_package)
    if target_package and not ui_df.empty:
        package_mask = ui_df["screen"].map(lambda value: extract_app_package(_clean(value)) in {"", target_package})
        ui_df = ui_df[package_mask].copy()
    if target_package and not metadata_df.empty and "package" in metadata_df.columns:
        metadata_df = metadata_df[metadata_df["package"].map(lambda value: _clean(value) in {"", target_package})].copy()

    results: List[dict] = []

    ui_rows = ui_df.dropna(subset=["timestamp"])
    if ui_rows.empty:
        for row_index, traffic_row in traffic_df.sort_values("timestamp").iterrows():
            results.append(build_result_for_traffic_row(traffic_row, allowed_domains, event_id=f"T{row_index + 1:03d}"))
        for row_index, metadata_row in metadata_df.sort_values("timestamp").iterrows():
            results.append(
                build_result_for_metadata_row(
                    metadata_row,
                    allowed_domains,
                    event_id=f"M{row_index + 1:03d}",
                )
            )

    for _, ui_row in ui_rows.iterrows():
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
        matched_metadata = metadata_df[
            (metadata_df["timestamp"] >= ui_time)
            & (metadata_df["timestamp"] <= ui_time + window_seconds)
        ].sort_values("timestamp")

        for _, metadata_row in matched_metadata.iterrows():
            results.append(
                build_result_for_metadata_row(
                    metadata_row,
                    allowed_domains,
                    event_id=event_id,
                    ui_time=ui_time,
                    app_package=app_package,
                    screen=screen,
                    action=action,
                    element_text=element_text,
                )
            )

        if matched_traffic.empty and matched_metadata.empty:
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
                    "observability_status": no_traffic_status(traffic_log_had_rows, metadata_log_had_rows),
                    "metadata_source": "",
                    "destination_ip": "",
                    "destination_port": "",
                    "protocol": "",
                    "bytes_sent": "",
                    "bytes_received": "",
                    "domain": "",
                    "destination_party": "none",
                    "scheme": "",
                    "method": "",
                    "url": "",
                    "status_code": "",
                    "content_type": "",
                    "request_size": "",
                    "response_size": "",
                    "response_timestamp": "",
                    "duration_ms": "",
                    "error": "",
                    "risk": "Unknown",
                    "risk_category": "観測不能",
                    "risk_rule": "no_observed_traffic",
                    "risk_signal": "no_observed_network_in_window",
                    "data_categories": "",
                    "reason": f"操作後{window_seconds:g}秒以内にmitmproxy/VPN/pcapで通信は観測されませんでした。通信なしとは断定せず観測不能として扱います。",
                }
            )
            continue

        for _, traffic_row in matched_traffic.iterrows():
            traffic_time = float(traffic_row["timestamp"])
            delta = round(traffic_time - ui_time, 3)
            url = _clean(traffic_row.get("url"))
            scheme, domain = _derive_scheme_domain(
                traffic_row.get("scheme"),
                traffic_row.get("domain"),
                url,
            )
            decision = classify_risk(
                scheme=scheme,
                domain=domain,
                ui_text=element_text,
                allowed_domains=allowed_domains,
                url=url,
                time_delta=delta,
                event_id=event_id,
                status_code=traffic_row.get("status_code"),
                method=traffic_row.get("method"),
                request_size=traffic_row.get("request_size"),
                error=traffic_row.get("error"),
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
                    "observability_status": observability_status_for_decision(decision),
                    **_empty_metadata_fields(),
                    "domain": domain,
                    "destination_party": destination_party(domain, allowed_domains),
                    "scheme": scheme,
                    "method": _clean(traffic_row.get("method")),
                    "url": url,
                    "status_code": _clean(traffic_row.get("status_code")),
                    "content_type": _clean(traffic_row.get("content_type")),
                    "request_size": _clean(traffic_row.get("request_size")),
                    "response_size": _clean(traffic_row.get("response_size")),
                    "response_timestamp": _clean(traffic_row.get("response_timestamp")),
                    "duration_ms": _clean(traffic_row.get("duration_ms")),
                    "error": _clean(traffic_row.get("error")),
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
    parser = argparse.ArgumentParser(description="Classify captured traffic logs. UI logs are optional.")
    parser.add_argument("--ui-log", default=DEFAULT_UI_PATH, help="Optional path to ui_events.csv for UI correlation.")
    parser.add_argument("--traffic-log", default=DEFAULT_TRAFFIC_PATH, help="Path to traffic_logs.csv.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT_PATH, help="Path to write risk_results.csv.")
    parser.add_argument("--window", type=float, default=DEFAULT_WINDOW_SECONDS, help="Seconds after each UI event to correlate traffic.")
    parser.add_argument(
        "--allowed-domain",
        action="append",
        dest="allowed_domains",
        help="First-party/allowlisted domain. Can be specified multiple times.",
    )
    parser.add_argument("--target-package", default="", help="Only correlate UI/metadata rows belonging to this Android package.")
    parser.add_argument("--metadata-log", default="", help="Optional VPN/pcap metadata CSV, for example PCAPdroid export normalized to pcap_metadata.csv.")
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
            target_package=args.target_package,
            metadata_path=args.metadata_log,
        )
    except FileNotFoundError as exc:
        print(f"[Error] {exc}")
