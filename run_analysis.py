import argparse
import csv
import os
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import List, Optional


TRAFFIC_LOG_COLUMNS = ["timestamp", "scheme", "domain", "method", "url", "status_code", "content_type", "request_size", "response_size"]


@dataclass(frozen=True)
class ProxyState:
    host: str
    port: int
    previous_http_proxy: str
    reverse_configured: bool




def run(command: List[str], check: bool = True) -> subprocess.CompletedProcess:
    print("[RUN] " + " ".join(command))
    return subprocess.run(command, check=check)


def run_capture(command: List[str], check: bool = True) -> subprocess.CompletedProcess:
    print("[RUN] " + " ".join(command))
    return subprocess.run(command, check=check, text=True, capture_output=True)


def adb(command: List[str], serial: Optional[str] = None, check: bool = True) -> subprocess.CompletedProcess:
    base = ["adb"]
    if serial:
        base.extend(["-s", serial])
    return run_capture(base + command, check=check)


def adb_shell(command: List[str], serial: Optional[str] = None, check: bool = True) -> subprocess.CompletedProcess:
    return adb(["shell", *command], serial=serial, check=check)


def initialize_traffic_log(filepath: str, reset: bool = False) -> None:
    log_dir = os.path.dirname(filepath)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    if reset or not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(TRAFFIC_LOG_COLUMNS)
            f.flush()
            os.fsync(f.fileno())


def start_mitmproxy(listen_port: int) -> Optional[subprocess.Popen]:
    mitmdump = shutil.which("mitmdump")
    if not mitmdump:
        print("[WARN] mitmdump was not found. UI automation will run, but traffic_logs.csv will not be captured.")
        return None

    traffic_path = os.path.abspath("logs/traffic_logs.csv")
    script_path = os.path.abspath("capture_traffic.py")
    initialize_traffic_log(traffic_path, reset=True)

    command = [
        mitmdump,
        "-s",
        script_path,
        "--listen-port",
        str(listen_port),
        "--set",
        "block_global=false",
    ]
    env = os.environ.copy()
    env["TRAFFIC_LOG_PATH"] = traffic_path
    print("[MITM] Starting: " + " ".join(command))
    proc = subprocess.Popen(command, env=env)
    time.sleep(3)
    if proc.poll() is not None:
        print(f"[WARN] mitmdump exited early with status {proc.returncode}; traffic capture may be unavailable.")
    return proc


def warn_if_no_traffic_records(traffic_path: str = "logs/traffic_logs.csv") -> None:
    if not os.path.exists(traffic_path):
        print(f"[WARN] {traffic_path} was not created; mitmproxy did not start or could not load the capture script.")
        return

    with open(traffic_path, encoding="utf-8") as f:
        non_empty_lines = [line for line in f if line.strip()]

    if len(non_empty_lines) <= 1:
        print(
            f"[WARN] {traffic_path} contains only the header and no captured requests. "
            "Check that the app uses the configured Android HTTP proxy, the mitmproxy CA is trusted for HTTPS, "
            "and the tested actions actually perform network requests."
        )


def stop_process(proc: Optional[subprocess.Popen]) -> None:
    if not proc:
        return
    print("[MITM] Stopping mitmdump")
    time.sleep(1)
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def local_route_ip() -> str:
    """Return the host IP address normally reachable by a connected device."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]


def get_android_http_proxy(serial: Optional[str] = None) -> str:
    proc = adb_shell(["settings", "get", "global", "http_proxy"], serial=serial, check=False)
    if proc.returncode != 0:
        return ""
    value = proc.stdout.strip()
    return "" if value in {"", "null"} else value


def clear_android_http_proxy(serial: Optional[str] = None) -> None:
    # `:0` is Android's supported sentinel for clearing the global HTTP proxy.
    adb_shell(["settings", "put", "global", "http_proxy", ":0"], serial=serial, check=False)
    adb_shell(["settings", "delete", "global", "global_http_proxy_host"], serial=serial, check=False)
    adb_shell(["settings", "delete", "global", "global_http_proxy_port"], serial=serial, check=False)


def set_android_http_proxy(host: str, port: int, serial: Optional[str] = None) -> None:
    adb_shell(["settings", "put", "global", "http_proxy", f"{host}:{port}"], serial=serial)


def setup_device_proxy(
    listen_port: int,
    serial: Optional[str] = None,
    proxy_host: Optional[str] = None,
    use_adb_reverse: bool = True,
) -> ProxyState:
    previous_proxy = get_android_http_proxy(serial)
    reverse_configured = False

    if proxy_host:
        host = proxy_host
    elif use_adb_reverse:
        reverse = adb(["reverse", f"tcp:{listen_port}", f"tcp:{listen_port}"], serial=serial, check=False)
        reverse_configured = reverse.returncode == 0
        if reverse_configured:
            host = "127.0.0.1"
            print(f"[ADB] Configured reverse tcp:{listen_port} -> tcp:{listen_port}")
        else:
            host = local_route_ip()
            output = (reverse.stdout + reverse.stderr).strip()
            print(f"[WARN] adb reverse failed; falling back to host IP {host}. {output}")
    else:
        host = local_route_ip()

    set_android_http_proxy(host, listen_port, serial=serial)
    print(f"[ADB] Android global HTTP proxy set to {host}:{listen_port}")
    if previous_proxy:
        print(f"[ADB] Previous Android HTTP proxy was {previous_proxy}; it will be restored after analysis.")
    return ProxyState(host=host, port=listen_port, previous_http_proxy=previous_proxy, reverse_configured=reverse_configured)


def restore_device_proxy(state: Optional[ProxyState], serial: Optional[str] = None) -> None:
    if not state:
        return
    if state.previous_http_proxy:
        adb_shell(["settings", "put", "global", "http_proxy", state.previous_http_proxy], serial=serial, check=False)
        print(f"[ADB] Restored Android global HTTP proxy to {state.previous_http_proxy}")
    else:
        clear_android_http_proxy(serial=serial)
        print("[ADB] Cleared Android global HTTP proxy")
    if state.reverse_configured:
        adb(["reverse", "--remove", f"tcp:{state.port}"], serial=serial, check=False)
        print(f"[ADB] Removed reverse tcp:{state.port}")


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
    parser.add_argument(
        "--include-system-probes",
        action="store_true",
        help="Include Android/Google connectivity probe traffic such as generate_204 in correlation results.",
    )
    parser.add_argument("--skip-capture", action="store_true", help="Do not start mitmdump; use an existing traffic_logs.csv instead.")
    parser.add_argument(
        "--skip-proxy-setup",
        action="store_true",
        help="Do not change the Android global HTTP proxy. Use this only when the device is already routed through mitmproxy.",
    )
    parser.add_argument(
        "--proxy-host",
        help=(
            "Host/IP that the Android device should use for mitmproxy. By default adb reverse is used and "
            "the device proxy is set to 127.0.0.1:<listen-port>; if reverse fails, the host LAN IP is used."
        ),
    )
    parser.add_argument(
        "--no-adb-reverse",
        action="store_true",
        help="Do not create adb reverse for the mitmproxy port; use --proxy-host or the host LAN IP instead.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not os.path.exists(args.apk):
        print(f"[ERROR] APK file not found: {args.apk}", file=sys.stderr)
        return 1

    mitm_proc = None if args.skip_capture else start_mitmproxy(args.listen_port)
    proxy_state = None
    try:
        if not args.skip_capture and not args.skip_proxy_setup and mitm_proc is not None:
            proxy_state = setup_device_proxy(
                args.listen_port,
                serial=args.serial,
                proxy_host=args.proxy_host,
                use_adb_reverse=not args.no_adb_reverse,
            )

        command = [sys.executable, "auto_runner.py", "--apk", args.apk, "--max-events", str(args.max_events), "--wait", str(args.wait)]
        if args.package:
            command.extend(["--package", args.package])
        if args.serial:
            command.extend(["--serial", args.serial])
        run(command)
    finally:
        restore_device_proxy(proxy_state, serial=args.serial)
        stop_process(mitm_proc)

    if not args.skip_capture:
        warn_if_no_traffic_records()

    from analyze_logs import analyze

    analyze(
        window_seconds=args.window,
        allowed_domains=args.allowed_domains,
        include_system_probes=args.include_system_probes,
    )
    print("[DONE] Results are available in logs/risk_results.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
