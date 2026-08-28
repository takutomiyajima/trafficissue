"""Build an evidence-oriented report that joins static and dynamic analysis."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping


REPORT_SCHEMA_VERSION = "1.0"
OBSERVED_STATUSES = {"observed", "metadata_only"}
UNVERIFIED_STATUSES = {"tunnel_only", "unreadable_tls", "not_observed", "capture_failed"}


def _clean(value: object) -> str:
    if value is None or value != value:
        return ""
    return str(value).strip()


def _stable_id(prefix: str, *parts: object) -> str:
    value = "\x1f".join(_clean(part) for part in parts)
    return f"{prefix}_{hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]}"


def _static_domains(handoff: Mapping[str, object]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    items = handoff.get("expected_domains", [])
    if not isinstance(items, list):
        return result
    for item in items:
        if not isinstance(item, dict):
            continue
        domain = _clean(item.get("domain")).lower().rstrip(".")
        if domain:
            result[domain] = sorted({_clean(value) for value in item.get("static_evidence", []) if _clean(value)})
    return result


def _matches(observed_domain: str, expected_domain: str) -> bool:
    return observed_domain == expected_domain or observed_domain.endswith("." + expected_domain)


def _categories(value: object) -> set[str]:
    return {item.strip() for item in _clean(value).split(";") if item.strip()}


def _confidence(status: str, observability_status: str) -> str:
    if status == "Supported" and observability_status == "observed":
        return "high"
    if status == "Confirmed" and observability_status == "observed":
        return "high"
    if status == "Supported" or observability_status == "metadata_only":
        return "medium"
    if status == "Potential":
        return "low"
    return "unknown"


def _priority(row: Mapping[str, object], status: str) -> str:
    risk = _clean(row.get("risk"))
    if risk == "High":
        return "high"
    if risk == "Medium" or status in {"Potential", "Unverified"}:
        return "medium"
    if risk == "Low":
        return "low"
    return "unknown"


def build_integrated_report(
    result_rows: Iterable[Mapping[str, object]],
    static_handoff: Mapping[str, object] | None = None,
    capture_health: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Create observations, evidence and review findings without claiming intent."""

    handoff = dict(static_handoff or {})
    expected_domains = _static_domains(handoff)
    expected_categories = {
        _clean(value)
        for value in handoff.get("sensitive_data_categories", [])
        if _clean(value)
    }
    matched_static_domains: set[str] = set()
    matched_static_categories: set[str] = set()
    observations: list[dict[str, object]] = []
    evidence: list[dict[str, object]] = []
    findings: list[dict[str, object]] = []

    for index, raw_row in enumerate(result_rows, start=1):
        row = dict(raw_row)
        domain = _clean(row.get("domain")).lower().rstrip(".")
        observability = _clean(row.get("observability_status")) or "unknown"
        observation_id = _stable_id(
            "obs", index, row.get("event_id"), row.get("traffic_timestamp"), domain, observability
        )
        observations.append(
            {
                "observation_id": observation_id,
                "source": _clean(row.get("metadata_source")) or "dynamic_analysis",
                "event_id": _clean(row.get("event_id")),
                "observability_status": observability,
                "domain": domain or None,
                "scheme": _clean(row.get("scheme")) or None,
                "method": _clean(row.get("method")) or None,
                "risk_rule": _clean(row.get("risk_rule")) or None,
                "capture_detail": _clean(row.get("capture_detail")) or None,
                "traffic_owner": _clean(row.get("traffic_owner")) or "unknown",
                "owner_confidence": _clean(row.get("owner_confidence")) or "unknown",
            }
        )

        static_matches = sorted(
            candidate for candidate in expected_domains if domain and _matches(domain, candidate)
        )
        dynamic_categories = _categories(row.get("data_categories"))
        category_matches = sorted(dynamic_categories & expected_categories)
        matched_static_domains.update(static_matches)
        matched_static_categories.update(category_matches)
        if observability in UNVERIFIED_STATUSES:
            status = "Unverified"
        elif "owner_confidence" in row and _clean(row.get("owner_confidence")) in {"", "unknown"}:
            status = "Unverified"
        elif (static_matches or category_matches) and observability in OBSERVED_STATUSES:
            status = "Supported"
        elif observability in OBSERVED_STATUSES:
            status = "Confirmed"
        else:
            status = "Unverified"

        evidence_ids: list[str] = []
        dynamic_evidence_id = _stable_id("ev", observation_id, "dynamic", observability)
        evidence.append(
            {
                "evidence_id": dynamic_evidence_id,
                "observation_id": observation_id,
                "source": "dynamic",
                "type": "network_observation" if observability in OBSERVED_STATUSES else "observability_limit",
                "value": domain or observability,
            }
        )
        evidence_ids.append(dynamic_evidence_id)
        for candidate in static_matches:
            static_evidence_id = _stable_id("ev", candidate, "static")
            if not any(item["evidence_id"] == static_evidence_id for item in evidence):
                evidence.append(
                    {
                        "evidence_id": static_evidence_id,
                        "observation_id": None,
                        "source": "static",
                        "type": "embedded_domain_candidate",
                        "value": candidate,
                        "details": expected_domains[candidate],
                    }
                )
            evidence_ids.append(static_evidence_id)
        for category in category_matches:
            static_evidence_id = _stable_id("ev", category, "static_category")
            if not any(item["evidence_id"] == static_evidence_id for item in evidence):
                evidence.append(
                    {
                        "evidence_id": static_evidence_id,
                        "observation_id": None,
                        "source": "static",
                        "type": "sensitive_data_category_candidate",
                        "value": category,
                    }
                )
            evidence_ids.append(static_evidence_id)

        finding_id = _stable_id("finding", row.get("event_id"), domain, row.get("risk_rule"), status)
        findings.append(
            {
                "finding_id": finding_id,
                "category": _clean(row.get("risk_category")) or "通信確認",
                "status": status,
                "confidence": _confidence(status, observability),
                "review_priority": _priority(row, status),
                "domain": domain or None,
                "event_id": _clean(row.get("event_id")) or None,
                "evidence_ids": evidence_ids,
                "review_question": (
                    "この通信または実装候補は開発意図と一致していますか。"
                    if status != "Unverified"
                    else "観測条件または操作範囲を変えて再確認する必要があります。"
                ),
            }
        )

    for domain, details in expected_domains.items():
        if domain in matched_static_domains:
            continue
        evidence_id = _stable_id("ev", domain, "static")
        if not any(item["evidence_id"] == evidence_id for item in evidence):
            evidence.append(
                {
                    "evidence_id": evidence_id,
                    "observation_id": None,
                    "source": "static",
                    "type": "embedded_domain_candidate",
                    "value": domain,
                    "details": details,
                }
            )
        findings.append(
            {
                "finding_id": _stable_id("finding", domain, "static_only"),
                "category": "静的通信先候補",
                "status": "Potential",
                "confidence": "low",
                "review_priority": "medium",
                "domain": domain,
                "event_id": None,
                "evidence_ids": [evidence_id],
                "review_question": "静的に存在するこの通信先候補は、想定した機能またはSDK由来ですか。",
            }
        )

    for category in sorted(expected_categories - matched_static_categories):
        evidence_id = _stable_id("ev", category, "static_category")
        if not any(item["evidence_id"] == evidence_id for item in evidence):
            evidence.append(
                {
                    "evidence_id": evidence_id,
                    "observation_id": None,
                    "source": "static",
                    "type": "sensitive_data_category_candidate",
                    "value": category,
                }
            )
        findings.append(
            {
                "finding_id": _stable_id("finding", category, "static_category_only"),
                "category": category,
                "status": "Potential",
                "confidence": "low",
                "review_priority": "medium",
                "domain": None,
                "event_id": None,
                "evidence_ids": [evidence_id],
                "review_question": "このデータカテゴリに関する実装候補は開発意図と一致していますか。",
            }
        )

    status_counts = {name: 0 for name in ("Confirmed", "Potential", "Supported", "Unverified")}
    for finding in findings:
        status_counts[str(finding["status"])] += 1

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope_statement": (
            "This report supports developer review and does not automatically determine "
            "whether behavior matches development intent or whether the app is safe."
        ),
        "application": {"package_name": handoff.get("package_name")},
        "capture_health": dict(capture_health or {}),
        "summary": {"status_counts": status_counts},
        "observations": observations,
        "evidence": evidence,
        "findings": findings,
    }


def write_integrated_report(report: Mapping[str, object], output_path: str) -> None:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
