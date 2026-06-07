import argparse
import os
import shutil
import subprocess
import sys
import time
from typing import List, Optional



def run(command: List[str], check: bool = True) -> subprocess.CompletedProcess:
    print("[RUN] " + " ".join(command))
    return subprocess.run(command, check=check)


def start_mitmproxy(listen_port: int) -> Optional[subprocess.Popen]:
    mitmdump = shutil.which("mitmdump")
    if not mitmdump:
        print("[WARN] mitmdump was not found. UI automation will run, but traffic_logs.csv will not be captured.")
        return None
    os.makedirs("logs", exist_ok=True)
    traffic_path = "logs/traffic_logs.csv"
    if os.path.exists(traffic_path):
        os.remove(traffic_path)
    command = [mitmdump, "-s", "capture_traffic.py", "--listen-port", str(listen_port)]
    print("[MITM] Starting: " + " ".join(command))
    proc = subprocess.Popen(command)
    time.sleep(3)
    return proc


def stop_process(proc: Optional[subprocess.Popen]) -> None:
    if not proc:
        return
    print("[MITM] Stopping mitmdump")
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the full APK analysis flow: traffic capture, APK install/start, UI auto exploration, and risk analysis."
    )
    parser.add_argument("apk", help="Path to the APK file to analyze.")
    parser.add_argument("--serial", help="ADB device serial. Optional when only one device is connected.")
    parser.add_argument("--package", help="Package name override if it cannot be extracted from the APK.")
    parser.add_argument("--max-events", type=int, default=30, help="Maximum number of UI taps to perform.")
    parser.add_argument("--wait", type=int, default=5, help="Seconds to wait after app start and each tap.")
    parser.add_argument("--listen-port", type=int, default=8080, help="mitmproxy listen port.")
    parser.add_argument("--window", type=float, default=5.0, help="Seconds after each UI event to correlate traffic.")
    parser.add_argument(
        "--allowed-domain",
        action="append",
        dest="allowed_domains",
        help="First-party/allowlisted domain. Can be specified multiple times.",
    )
    parser.add_argument("--skip-capture", action="store_true", help="Do not start mitmdump; use an existing traffic_logs.csv instead.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not os.path.exists(args.apk):
        print(f"[ERROR] APK file not found: {args.apk}", file=sys.stderr)
        return 1

    mitm_proc = None if args.skip_capture else start_mitmproxy(args.listen_port)
    try:
        command = [sys.executable, "auto_runner.py", "--apk", args.apk, "--max-events", str(args.max_events), "--wait", str(args.wait)]
        if args.package:
            command.extend(["--package", args.package])
        if args.serial:
            command.extend(["--serial", args.serial])
        run(command)
    finally:
        stop_process(mitm_proc)

    from analyze_logs import analyze

    analyze(window_seconds=args.window, allowed_domains=args.allowed_domains)
    print("[DONE] Results are available in logs/risk_results.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
