import argparse
import csv
import datetime
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


LOG_PATH = "logs/ui_events.csv"
DEFAULT_WAIT_SECONDS = 5
DEFAULT_MAX_EVENTS = 30


def run_command(command: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=check, text=True, capture_output=True)


def adb(command: List[str], serial: Optional[str] = None, check: bool = True) -> subprocess.CompletedProcess:
    base = ["adb"]
    if serial:
        base.extend(["-s", serial])
    return run_command(base + command, check=check)


def list_installed_packages(serial: Optional[str] = None) -> Set[str]:
    proc = adb(["shell", "pm", "list", "packages"], serial=serial)
    packages: Set[str] = set()
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            packages.add(line.replace("package:", "", 1).strip())
    return packages


def extract_package_with_android_tools(apk_path: str) -> Optional[str]:
    # Prefer Android SDK tools when available. They understand binary AndroidManifest.xml.
    for tool, command in (
        ("aapt", ["aapt", "dump", "badging", apk_path]),
        ("aapt2", ["aapt2", "dump", "badging", apk_path]),
    ):
        if not shutil.which(tool):
            continue
        proc = run_command(command, check=False)
        match = re.search(r"package: name='([^']+)'", proc.stdout)
        if match:
            return match.group(1)
    return None


def install_apk_and_get_package(apk_path: str, serial: Optional[str] = None) -> str:
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    package_from_tools = extract_package_with_android_tools(apk_path)
    before_packages = list_installed_packages(serial)

    print(f"[APK] Installing: {apk_path}")
    install_proc = adb(["install", "-r", apk_path], serial=serial, check=False)
    install_output = (install_proc.stdout + install_proc.stderr).strip()
    if install_proc.returncode != 0 and "INSTALL_FAILED_ALREADY_EXISTS" not in install_output:
        raise RuntimeError(f"adb install failed:\n{install_output}")

    after_packages = list_installed_packages(serial)
    new_packages = sorted(after_packages - before_packages)

    if package_from_tools:
        print(f"[APK] Package detected by Android SDK tools: {package_from_tools}")
        return package_from_tools
    if len(new_packages) == 1:
        print(f"[APK] Package detected from install delta: {new_packages[0]}")
        return new_packages[0]
    if new_packages:
        raise RuntimeError(
            "Multiple packages appeared after install. Please pass --package explicitly: "
            + ", ".join(new_packages)
        )
    raise RuntimeError(
        "Could not determine package name from APK. Install aapt/aapt2 or pass --package explicitly."
    )


def init_log(filepath: str) -> None:
    log_dir = os.path.dirname(filepath)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["event_id", "timestamp", "screen", "action", "element_text", "resource_id", "bounds"])


def parse_bounds(bounds: str) -> Optional[Tuple[int, int, int, int]]:
    match = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds or "")
    if not match:
        return None
    return tuple(int(group) for group in match.groups())  # type: ignore[return-value]


def center_of(bounds: str) -> Optional[Tuple[int, int]]:
    parsed = parse_bounds(bounds)
    if not parsed:
        return None
    x1, y1, x2, y2 = parsed
    if x2 <= x1 or y2 <= y1:
        return None
    return ((x1 + x2) // 2, (y1 + y2) // 2)


def node_label(node: ET.Element) -> str:
    for key in ("text", "content-desc", "resource-id", "class"):
        value = node.attrib.get(key, "").strip()
        if value:
            return value
    return "Unnamed clickable element"


def clickable_nodes(xml: str) -> Iterable[Dict[str, str]]:
    root = ET.fromstring(xml)
    for node in root.iter("node"):
        if node.attrib.get("clickable") != "true":
            continue
        bounds = node.attrib.get("bounds", "")
        if not center_of(bounds):
            continue
        yield {
            "text": node.attrib.get("text", ""),
            "description": node.attrib.get("content-desc", ""),
            "resource_id": node.attrib.get("resource-id", ""),
            "class": node.attrib.get("class", ""),
            "bounds": bounds,
            "label": node_label(node),
        }


def screen_name(d: Any, package_name: str) -> str:
    try:
        current = d.app_current()
        activity = current.get("activity") or ""
        package = current.get("package") or package_name
        return f"{package}/{activity}"
    except Exception:
        return package_name


def signature(node: Dict[str, str], screen: str) -> str:
    stable_parts = [
        screen,
        node.get("resource_id", ""),
        node.get("text", ""),
        node.get("description", ""),
        node.get("class", ""),
        node.get("bounds", ""),
    ]
    return "|".join(stable_parts)


def log_event(filepath: str, event_counter: int, screen: str, node: Dict[str, str]) -> int:
    timestamp = int(datetime.datetime.now().timestamp())
    with open(filepath, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            f"E{event_counter:03d}",
            timestamp,
            screen,
            "tap",
            node.get("label", ""),
            node.get("resource_id", ""),
            node.get("bounds", ""),
        ])
    return timestamp


def auto_explore(
    d: Any,
    package_name: str,
    filepath: str,
    max_events: int,
    wait_seconds: int,
) -> None:
    print(f"[UI] Starting app: {package_name}")
    print(f"[UI] Framework: {framework}; strategy: {strategy}")
    d.app_start(package_name)
    time.sleep(wait_seconds)

    visited: Set[str] = set()
    event_counter = 1
    idle_rounds = 0

    while event_counter <= max_events and idle_rounds < 3:
        current_screen = screen_name(d, package_name)
        try:
            xml = d.dump_hierarchy(compressed=False)
            candidates = list(clickable_nodes(xml))
        except Exception as exc:
            print(f"[UI] Failed to dump hierarchy: {exc}")
            break

        next_node = None
        for node in candidates:
            sig = signature(node, current_screen)
            if sig not in visited:
                next_node = node
                visited.add(sig)
                break

        if not next_node:
            idle_rounds += 1
            print(f"[UI] No new clickable elements on {current_screen}; pressing back ({idle_rounds}/3).")
            d.press("back")
            time.sleep(1)
            continue

        idle_rounds = 0
        center = center_of(next_node["bounds"])
        if not center:
            continue
        x, y = center
        timestamp = log_event(filepath, event_counter, current_screen, next_node)
        print(
            f"[UI] E{event_counter:03d}: tapped '{next_node['label']}' "
            f"at ({x}, {y}) on {current_screen} at {timestamp}"
        )
        d.click(x, y)
        event_counter += 1
        time.sleep(wait_seconds)

        try:
            current_package = d.app_current().get("package")
            if current_package != package_name:
                print(f"[UI] Returned from external package: {current_package}")
                d.press("back")
                time.sleep(1)
        except Exception:
            pass

    print(f"[UI] Automation finished. Recorded {event_counter - 1} UI events.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install an APK if provided, start the target app, and automatically explore clickable UI elements."
    )
    parser.add_argument("--apk", help="Path to the APK file to install and analyze automatically.")
    parser.add_argument("--package", help="Package name to analyze. When used with --apk, this overrides automatic package detection after install.")
    parser.add_argument("--serial", help="ADB device serial. Optional when only one device is connected.")
    parser.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS, help="Maximum number of UI taps to perform.")
    parser.add_argument("--wait", type=int, default=DEFAULT_WAIT_SECONDS, help="Seconds to wait after app start and each tap.")
    parser.add_argument("--log", default=LOG_PATH, help="CSV path for UI event logs.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.apk and not args.package:
        raise SystemExit("Either --apk or --package is required.")

    import uiautomator2 as u2

    d = u2.connect(args.serial) if args.serial else u2.connect()
    detected_package = install_apk_and_get_package(args.apk, serial=args.serial) if args.apk else None
    package_name = args.package or detected_package
    if not package_name:
        raise SystemExit("Package name could not be determined.")

    init_log(args.log)
    auto_explore(d, package_name, args.log, args.max_events, args.wait)


if __name__ == "__main__":
    main()
