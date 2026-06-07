import csv
import datetime
import os
from pathlib import Path
from mitmproxy import http


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_TRAFFIC_LOG_PATH = str(PROJECT_ROOT / "logs" / "traffic_logs.csv")
TRAFFIC_LOG_COLUMNS = ["timestamp", "scheme", "domain", "method", "url", "status_code", "content_type", "request_size", "response_size"]


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
    def __init__(self, filepath: str = DEFAULT_TRAFFIC_LOG_PATH):
        self.filepath = filepath
        self._request_rows = {}
        self._ensure_log_file(reset=True)

    def _ensure_log_file(self, reset: bool = False) -> None:
        initialize_traffic_log(self.filepath, reset=reset)

    def _flow_key(self, flow: http.HTTPFlow) -> str:
        return str(getattr(flow, "id", id(flow)))

    def _build_row(self, flow: http.HTTPFlow, status_code: int = 0) -> list[object]:
        timestamp = int(datetime.datetime.now().timestamp())
        request_body = flow.request.raw_content or b""
        response_body = flow.response.raw_content if flow.response and flow.response.raw_content else b""
        return [
            timestamp,
            flow.request.scheme,
            flow.request.host,
            flow.request.method,
            flow.request.url,
            status_code,
            flow.request.headers.get("content-type", ""),
            len(request_body),
            len(response_body),
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
        self._request_rows[self._flow_key(flow)] = self._write_flow(flow, 0)

    def response(self, flow: http.HTTPFlow):
        status_code = flow.response.status_code if flow.response else 0
        row = self._build_row(flow, status_code=status_code)
        request_row = self._request_rows.pop(self._flow_key(flow), None)
        if request_row is not None:
            row[0] = request_row[0]
        if request_row is None or not self._replace_row(request_row, row):
            self._append_row(row)

    def error(self, flow: http.HTTPFlow):
        row = self._build_row(flow, status_code=0)
        request_row = self._request_rows.pop(self._flow_key(flow), None)
        if request_row is not None:
            row[0] = request_row[0]
        if request_row is None or not self._replace_row(request_row, row):
            self._append_row(row)


addons = [TrafficLogger(os.environ.get("TRAFFIC_LOG_PATH", DEFAULT_TRAFFIC_LOG_PATH))]
