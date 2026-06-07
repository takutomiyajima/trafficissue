import csv
import datetime
import os
from pathlib import Path
from time import monotonic
from mitmproxy import http


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_TRAFFIC_LOG_PATH = str(PROJECT_ROOT / "logs" / "traffic_logs.csv")
TRAFFIC_LOG_COLUMNS = [
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


def _now_timestamp() -> float:
    return round(datetime.datetime.now().timestamp(), 3)


def initialize_traffic_log(filepath: str = DEFAULT_TRAFFIC_LOG_PATH, reset: bool = False) -> None:
    log_dir = os.path.dirname(filepath)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    if reset or not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(TRAFFIC_LOG_COLUMNS)
            f.flush()
            os.fsync(f.fileno())


class TrafficLogger:
    def __init__(self, filepath: str = DEFAULT_TRAFFIC_LOG_PATH, reset: bool = False):
        self.filepath = filepath
        self._request_rows = {}
        self._request_started_at = {}
        self._ensure_log_file(reset=reset)

    def _ensure_log_file(self, reset: bool = False) -> None:
        initialize_traffic_log(self.filepath, reset=reset)

    def _flow_key(self, flow: http.HTTPFlow) -> str:
        return str(getattr(flow, "id", id(flow)))

    def _build_row(
        self,
        flow: http.HTTPFlow,
        status_code: int = 0,
        request_timestamp: object = None,
        response_timestamp: object = "",
        duration_ms: object = "",
        error: str = "",
        scheme: str = "",
        url: str = "",
    ) -> list[object]:
        request_timestamp = _now_timestamp() if request_timestamp is None else request_timestamp
        request_body = flow.request.raw_content or b""
        response_body = flow.response.raw_content if flow.response and flow.response.raw_content else b""
        return [
            request_timestamp,
            scheme or flow.request.scheme,
            flow.request.host,
            flow.request.method,
            url or flow.request.url,
            status_code,
            flow.request.headers.get("content-type", ""),
            len(request_body),
            len(response_body),
            response_timestamp,
            duration_ms,
            error,
        ]

    def _append_row(self, row: list[object]) -> None:
        self._ensure_log_file()
        with open(self.filepath, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)
            f.flush()
            os.fsync(f.fileno())

    def _replace_row(self, old_row: list[object], new_row: list[object]) -> bool:
        self._ensure_log_file()
        with open(self.filepath, newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))

        old_row_as_text = [str(value) for value in old_row]
        replaced = False
        for index, row in enumerate(rows):
            if row == old_row_as_text:
                rows[index] = [str(value) for value in new_row]
                replaced = True
                break

        if not replaced:
            return False

        with open(self.filepath, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(rows)
            f.flush()
            os.fsync(f.fileno())
        return True

    def _write_flow(self, flow: http.HTTPFlow, status_code: int = 0) -> list[object]:
        row = self._build_row(flow, status_code=status_code)
        self._append_row(row)
        return row

    def request(self, flow: http.HTTPFlow):
        key = self._flow_key(flow)
        existing_row = self._request_rows.get(key)
        if key not in self._request_started_at:
            self._request_started_at[key] = monotonic()
        row = self._build_row(flow, status_code=0)
        if existing_row is not None and self._replace_row(existing_row, row):
            self._request_rows[key] = row
        else:
            self._request_rows[key] = row
            self._append_row(row)

    def http_connect(self, flow: http.HTTPFlow):
        """Record HTTPS tunnel attempts even when TLS interception fails before request()."""
        key = self._flow_key(flow)
        if key in self._request_rows:
            return
        self._request_started_at[key] = monotonic()
        status_code = flow.response.status_code if flow.response else 0
        host = flow.request.host
        port = getattr(flow.request, "port", 443)
        url = f"https://{host}:{port}" if port else f"https://{host}"
        self._request_rows[key] = self._build_row(
            flow,
            status_code=status_code,
            scheme="https",
            url=url,
            error="https_connect_tunnel",
        )
        self._append_row(self._request_rows[key])

    def response(self, flow: http.HTTPFlow):
        key = self._flow_key(flow)
        status_code = flow.response.status_code if flow.response else 0
        request_row = self._request_rows.pop(key, None)
        request_started_at = self._request_started_at.pop(key, None)
        response_timestamp = _now_timestamp()
        duration_ms = round((monotonic() - request_started_at) * 1000, 1) if request_started_at is not None else ""
        row = self._build_row(
            flow,
            status_code=status_code,
            request_timestamp=request_row[0] if request_row is not None else None,
            response_timestamp=response_timestamp,
            duration_ms=duration_ms,
        )
        if request_row is None or not self._replace_row(request_row, row):
            self._append_row(row)

    def error(self, flow: http.HTTPFlow):
        key = self._flow_key(flow)
        request_row = self._request_rows.pop(key, None)
        request_started_at = self._request_started_at.pop(key, None)
        response_timestamp = _now_timestamp()
        duration_ms = round((monotonic() - request_started_at) * 1000, 1) if request_started_at is not None else ""
        message = str(getattr(getattr(flow, "error", None), "msg", "connection_error"))
        row = self._build_row(
            flow,
            status_code=0,
            request_timestamp=request_row[0] if request_row is not None else None,
            response_timestamp=response_timestamp,
            duration_ms=duration_ms,
            error=message,
        )
        if request_row is None or not self._replace_row(request_row, row):
            self._append_row(row)


addons = [TrafficLogger(os.environ.get("TRAFFIC_LOG_PATH", DEFAULT_TRAFFIC_LOG_PATH))]
