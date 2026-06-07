import csv
import datetime
import os
from mitmproxy import http


DEFAULT_TRAFFIC_LOG_PATH = "logs/traffic_logs.csv"
TRAFFIC_LOG_COLUMNS = ["timestamp", "scheme", "domain", "method", "url", "status_code"]


class TrafficLogger:
    def __init__(self, filepath: str = DEFAULT_TRAFFIC_LOG_PATH):
        self.filepath = filepath
        self._ensure_log_file(reset=True)

    def _ensure_log_file(self, reset: bool = False) -> None:
        log_dir = os.path.dirname(self.filepath)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        if reset or not os.path.exists(self.filepath) or os.path.getsize(self.filepath) == 0:
            with open(self.filepath, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(TRAFFIC_LOG_COLUMNS)
                f.flush()
                os.fsync(f.fileno())

    def response(self, flow: http.HTTPFlow):
        timestamp = int(datetime.datetime.now().timestamp())
        row = [
            timestamp,
            flow.request.scheme,
            flow.request.host,
            flow.request.method,
            flow.request.url,
            flow.response.status_code if flow.response else 0,
        ]

        self._ensure_log_file()
        with open(self.filepath, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)
            f.flush()
            os.fsync(f.fileno())


addons = [TrafficLogger(os.environ.get("TRAFFIC_LOG_PATH", DEFAULT_TRAFFIC_LOG_PATH))]
