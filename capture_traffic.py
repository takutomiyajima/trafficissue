import datetime
import csv
import os
from mitmproxy import http

class TrafficLogger:
    def __init__(self):
        self.filepath = "logs/traffic_logs.csv"
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        
        # 初回のみヘッダーを作成
        if not os.path.exists(self.filepath):
            with open(self.filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "scheme", "domain", "method", "url", "status_code"])

    def response(self, flow: http.HTTPFlow):
        # UNIXタイムスタンプを取得
        timestamp = int(datetime.datetime.now().timestamp())
        scheme = flow.request.scheme
        domain = flow.request.host
        method = flow.request.method
        url = flow.request.url
        status_code = flow.response.status_code if flow.response else 0

        # 通信ログを追記
        with open(self.filepath, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, scheme, domain, method, url, status_code])

addons = [TrafficLogger()]