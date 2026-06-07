from __future__ import annotations

import argparse
import csv
import os
from datetime import datetime, timezone
from typing import Iterable

OUTPUT_COLUMNS = [
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

COLUMN_ALIASES = {
    "timestamp": "timestamp",
    "time": "timestamp",
    "ts": "timestamp",
    "date": "timestamp",
    "datetime": "timestamp",
    "app": "package",
    "package": "package",
    "package_name": "package",
    "uid_name": "package",
    "host": "destination_host",
    "hostname": "destination_host",
    "sni": "destination_host",
    "server_name": "destination_host",
    "remote_host": "destination_host",
    "dst_host": "destination_host",
    "destination_host": "destination_host",
    "ip": "destination_ip",
    "dst_ip": "destination_ip",
    "dest_ip": "destination_ip",
    "remote_ip": "destination_ip",
    "destination_ip": "destination_ip",
    "destination_address": "destination_ip",
    "port": "destination_port",
    "dst_port": "destination_port",
    "remote_port": "destination_port",
    "destination_port": "destination_port",
    "protocol": "protocol",
    "l4_proto": "protocol",
    "sent_bytes": "bytes_sent",
    "bytes_sent": "bytes_sent",
    "upload_bytes": "bytes_sent",
    "rcvd_bytes": "bytes_received",
    "received_bytes": "bytes_received",
    "recv_bytes": "bytes_received",
    "download_bytes": "bytes_received",
    "bytes_received": "bytes_received",
    "source": "source",
}


def clean(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def normalize_header(header: str) -> str:
    return clean(header).lstrip("\ufeff").lower().replace(" ", "_").replace("-", "_")


def parse_timestamp(value: str) -> str:
    """Return epoch seconds accepted by analyze_logs.py from epoch/ISO-like inputs."""
    value = clean(value)
    if not value:
        return ""
    try:
        number = float(value)
    except ValueError:
        number = None
    if number is not None:
        if number > 10_000_000_000:
            number = number / 1000.0
        return f"{number:.3f}".rstrip("0").rstrip(".")

    normalized = value.replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            dt = datetime.fromisoformat(normalized) if fmt is None else datetime.strptime(value, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return f"{dt.timestamp():.3f}".rstrip("0").rstrip(".")
    return value


def normalized_rows(rows: Iterable[dict[str, str]], source: str) -> list[dict[str, str]]:
    output_rows = []
    for row in rows:
        normalized = {column: "" for column in OUTPUT_COLUMNS}
        for key, value in row.items():
            canonical = COLUMN_ALIASES.get(normalize_header(key))
            if canonical and not normalized[canonical]:
                normalized[canonical] = clean(value)
        normalized["timestamp"] = parse_timestamp(normalized["timestamp"])
        if source and not normalized["source"]:
            normalized["source"] = source
        if any(normalized[column] for column in OUTPUT_COLUMNS if column != "source"):
            output_rows.append(normalized)
    return output_rows


def normalize_file(input_path: str, output_path: str, source: str = "pcapdroid") -> int:
    with open(input_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = normalized_rows(reader, source=source)

    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize PCAPdroid/VPN CSV exports for analyze_logs.py.")
    parser.add_argument("input", help="Raw PCAPdroid/VPN CSV export.")
    parser.add_argument("--output", default="logs/pcap_metadata.csv", help="Normalized metadata CSV path.")
    parser.add_argument("--source", default="pcapdroid", help="Value to write when the source column is absent.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    count = normalize_file(args.input, args.output, source=args.source)
    print(f"[PCAP] Wrote {count} normalized metadata rows to {args.output}")
