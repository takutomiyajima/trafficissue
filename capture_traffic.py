import csv
import datetime
import os
from mitmproxy import http


DEFAULT_TRAFFIC_LOG_PATH = "logs/traffic_logs.csv"
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
        self._ensure_log_file(reset=True)

    def _ensure_log_file(self, reset: bool = False) -> None:
        initialize_traffic_log(self.filepath, reset=reset)

    def _write_flow(self, flow: http.HTTPFlow, status_code: int = 0) -> None:
        timestamp = int(datetime.datetime.now().timestamp())
        request_body = flow.request.raw_content or b""
        response_body = flow.response.raw_content if flow.response and flow.response.raw_content else b""
        row = [
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

        self._ensure_log_file()
        with open(self.filepath, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)
            f.flush()
            os.fsync(f.fileno())

    def response(self, flow: http.HTTPFlow):
        self._write_flow(flow, flow.response.status_code if flow.response else 0)

    def error(self, flow: http.HTTPFlow):
        self._write_flow(flow, 0)


addons = [TrafficLogger(os.environ.get("TRAFFIC_LOG_PATH", DEFAULT_TRAFFIC_LOG_PATH))]
