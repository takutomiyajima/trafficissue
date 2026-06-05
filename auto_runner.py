import argparse
import csv
import datetime
import importlib.util
import os
import sys
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
import zipfile
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

LOG_PATH = "logs/ui_events.csv"
DEFAULT_WAIT_SECONDS = 5
DEFAULT_MAX_EVENTS = 30
DEFAULT_GRID_ROWS = 5
DEFAULT_GRID_COLS = 4


def run_command(command: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=check, text=True, capture_output=True)


def ensure_executable(name: str, install_hint: str) -> None:
    if not shutil.which(name):
        raise RuntimeError(f"Required executable '{name}' was not found. {install_hint}")


def ensure_python_dependency(module: str, install_hint: str) -> None:
    if importlib.util.find_spec(module) is None:
        raise RuntimeError(f"Required Python module '{module}' was not found. {install_hint}")


def format_completed_process_error(exc: subprocess.CalledProcessError) -> str:
    stdout = (exc.stdout or "").strip()
    stderr = (exc.stderr or "").strip()
    details = [f"Command failed with exit code {exc.returncode}: {' '.join(exc.cmd)}"]
    if stdout:
        details.append(f"stdout:\n{stdout}")
    if stderr:
        details.append(f"stderr:\n{stderr}")
    return "\n".join(details)


def adb(command: List[str], serial: Optional[str] = None, check: bool = True) -> subprocess.CompletedProcess:
    ensure_executable("adb", "Install Android platform-tools and make sure adb is in PATH.")
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


def detect_framework(apk_path: Optional[str]) -> Tuple[str, List[str]]:
    """Infer the app framework from APK contents to choose safer exploration fallbacks."""
    if not apk_path or not os.path.exists(apk_path):
        return "unknown", []

    try:
        with zipfile.ZipFile(apk_path) as apk:
            names = [name.lower() for name in apk.namelist()]
    except zipfile.BadZipFile:
        return "unknown", ["apk_not_readable_as_zip"]

    checks: Sequence[Tuple[str, Sequence[str]]] = (
        ("flutter", ("assets/flutter_assets/", "libflutter.so")),
        ("unity", ("assets/bin/data/", "libunity.so")),
        ("react_native", ("assets/index.android.bundle", "libreactnativejni.so")),
        ("webview", ("assets/www/", "cordova.js", "capacitor.config")),
    )
    for framework, markers in checks:
        matched = [marker for marker in markers if any(marker in name for name in names)]
        if matched:
            return framework, matched

    if any(name.endswith("classes.dex") for name in names):
        return "native_or_unknown", ["classes.dex"]
    return "unknown", []


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
        writer.writerow([
            "event_id",
            "timestamp",
            "screen",
            "action",
            "strategy",
            "framework",
            "element_text",
            "resource_id",
            "bounds",
            "x",
            "y",
            "screenshot_before",
            "screenshot_after",
        ])


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


def clickable_nodes(xml: str) -> Iterable[Dict[str, Any]]:
    root = ET.fromstring(xml)
    for node in root.iter("node"):
        if node.attrib.get("clickable") != "true":
            continue
        bounds = node.attrib.get("bounds", "")
        center = center_of(bounds)
        if not center:
            continue
        x, y = center
        yield {
            "text": node.attrib.get("text", ""),
            "description": node.attrib.get("content-desc", ""),
            "resource_id": node.attrib.get("resource-id", ""),
            "class": node.attrib.get("class", ""),
            "bounds": bounds,
            "label": node_label(node),
            "x": x,
            "y": y,
        }


def screen_name(d: Any, package_name: str) -> str:
    try:
        current = d.app_current()
        activity = current.get("activity") or ""
        package = current.get("package") or package_name
        return f"{package}/{activity}"
    except Exception:
        return package_name


def signature(node: Dict[str, Any], screen: str, strategy: str) -> str:
    stable_parts = [
        strategy,
        screen,
        str(node.get("resource_id", "")),
        str(node.get("text", "")),
        str(node.get("description", "")),
        str(node.get("class", "")),
        str(node.get("bounds", "")),
        str(node.get("x", "")),
        str(node.get("y", "")),
    ]
    return "|".join(stable_parts)


def display_size(d: Any) -> Tuple[int, int]:
    for getter in (lambda: d.window_size(), lambda: d.info):
        try:
            value = getter()
        except Exception:
            continue
        if isinstance(value, dict):
            width = value.get("displayWidth") or value.get("width")
            height = value.get("displayHeight") or value.get("height")
            if width and height:
                return int(width), int(height)
        if isinstance(value, (tuple, list)) and len(value) >= 2:
            return int(value[0]), int(value[1])
    return 1080, 1920


def grid_nodes(d: Any, rows: int, cols: int) -> Iterable[Dict[str, Any]]:
    width, height = display_size(d)
    top_margin = int(height * 0.12)
    bottom_margin = int(height * 0.08)
    usable_height = max(1, height - top_margin - bottom_margin)

    for row in range(rows):
        for col in range(cols):
            x = int((col + 0.5) * width / cols)
            y = int(top_margin + (row + 0.5) * usable_height / rows)
            yield {
                "text": "",
                "description": "",
                "resource_id": "",
                "class": "grid",
                "bounds": f"[{x},{y}][{x},{y}]",
                "label": f"GridTap_r{row + 1}_c{col + 1}",
                "x": x,
                "y": y,
            }


def screenshot_path(screenshot_dir: Optional[str], event_id: str, phase: str) -> str:
    if not screenshot_dir:
        return ""
    os.makedirs(screenshot_dir, exist_ok=True)
    return os.path.join(screenshot_dir, f"{event_id}_{phase}.png")


def take_screenshot(d: Any, filepath: str) -> str:
    if not filepath:
        return ""
    try:
        d.screenshot(filepath)
        return filepath
    except Exception as exc:
        print(f"[UI] Failed to save screenshot {filepath}: {exc}")
        return ""


def log_event(
    filepath: str,
    event_counter: int,
    timestamp: int,
    screen: str,
    node: Dict[str, Any],
    strategy: str,
    framework: str,
    screenshot_before: str = "",
    screenshot_after: str = "",
) -> None:
    with open(filepath, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            f"E{event_counter:03d}",
            timestamp,
            screen,
            "tap",
            strategy,
            framework,
            node.get("label", ""),
            node.get("resource_id", ""),
            node.get("bounds", ""),
            node.get("x", ""),
            node.get("y", ""),
            screenshot_before,
            screenshot_after,
        ])


def choose_accessibility_node(candidates: List[Dict[str, Any]], visited: Set[str], screen: str) -> Optional[Dict[str, Any]]:
    for node in candidates:
        sig = signature(node, screen, "accessibility")
        if sig not in visited:
            visited.add(sig)
            return node
    return None


def choose_grid_node(d: Any, visited: Set[str], screen: str, rows: int, cols: int) -> Optional[Dict[str, Any]]:
    for node in grid_nodes(d, rows, cols):
        sig = signature(node, screen, "grid")
        if sig not in visited:
            visited.add(sig)
            return node
    return None


def auto_explore(
    d: Any,
    package_name: str,
    filepath: str,
    max_events: int,
    wait_seconds: int,
    framework: str,
    strategy: str,
    grid_rows: int,
    grid_cols: int,
    screenshot_dir: Optional[str],
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
        next_node: Optional[Dict[str, Any]] = None
        selected_strategy = ""

        if strategy in ("auto", "accessibility"):
            try:
                xml = d.dump_hierarchy(compressed=False)
                candidates = list(clickable_nodes(xml))
                next_node = choose_accessibility_node(candidates, visited, current_screen)
                if next_node:
                    selected_strategy = "accessibility"
            except Exception as exc:
                print(f"[UI] Failed to dump hierarchy: {exc}")
                if strategy == "accessibility":
                    break

        if not next_node and strategy in ("auto", "grid"):
            next_node = choose_grid_node(d, visited, current_screen, grid_rows, grid_cols)
            if next_node:
                selected_strategy = "grid"

        if not next_node:
            idle_rounds += 1
            print(f"[UI] No new targets on {current_screen}; pressing back ({idle_rounds}/3).")
            d.press("back")
            time.sleep(1)
            continue

        idle_rounds = 0
        x, y = int(next_node["x"]), int(next_node["y"])
        event_id = f"E{event_counter:03d}"
        before_path = take_screenshot(d, screenshot_path(screenshot_dir, event_id, "before"))
        timestamp = int(datetime.datetime.now().timestamp())

        print(
            f"[UI] {event_id}: {selected_strategy} tapped '{next_node['label']}' "
            f"at ({x}, {y}) on {current_screen} at {timestamp}"
        )
        d.click(x, y)
        time.sleep(wait_seconds)
        after_path = take_screenshot(d, screenshot_path(screenshot_dir, event_id, "after"))
        log_event(filepath, event_counter, timestamp, current_screen, next_node, selected_strategy, framework, before_path, after_path)
        event_counter += 1

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
        description="Install an APK if provided, start the target app, and automatically explore UI targets with layered strategies."
    )
    parser.add_argument("--apk", help="Path to the APK file to install and analyze automatically.")
    parser.add_argument("--package", help="Package name to analyze. When used with --apk, this overrides automatic package detection after install.")
    parser.add_argument("--serial", help="ADB device serial. Optional when only one device is connected.")
    parser.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS, help="Maximum number of UI taps to perform.")
    parser.add_argument("--wait", type=int, default=DEFAULT_WAIT_SECONDS, help="Seconds to wait after app start and each tap.")
    parser.add_argument("--log", default=LOG_PATH, help="CSV path for UI event logs.")
    parser.add_argument(
        "--strategy",
        choices=("auto", "accessibility", "grid"),
        default="auto",
        help="UI exploration strategy. 'auto' tries accessibility first and falls back to grid taps.",
    )
    parser.add_argument("--grid-rows", type=int, default=DEFAULT_GRID_ROWS, help="Rows for grid fallback exploration.")
    parser.add_argument("--grid-cols", type=int, default=DEFAULT_GRID_COLS, help="Columns for grid fallback exploration.")
    parser.add_argument("--screenshots", default="", help="Directory to save before/after screenshots for each tap. Disabled by default.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.apk and not args.package:
        raise SystemExit("Either --apk or --package is required.")
    if args.grid_rows < 1 or args.grid_cols < 1:
        raise SystemExit("--grid-rows and --grid-cols must be greater than zero.")

    framework, markers = detect_framework(args.apk)
    print(f"[APK] Framework detected: {framework}" + (f" ({', '.join(markers)})" if markers else ""))

    ensure_python_dependency("uiautomator2", "Install it with: pip install uiautomator2")

    import uiautomator2 as u2

    d = u2.connect(args.serial) if args.serial else u2.connect()
    detected_package = install_apk_and_get_package(args.apk, serial=args.serial) if args.apk else None
    package_name = args.package or detected_package
    if not package_name:
        raise SystemExit("Package name could not be determined.")

    init_log(args.log)
    auto_explore(
        d,
        package_name,
        args.log,
        args.max_events,
        args.wait,
        framework,
        args.strategy,
        args.grid_rows,
        args.grid_cols,
        args.screenshots or None,
    )


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(f"[ERROR] {format_completed_process_error(exc)}", file=sys.stderr)
        raise SystemExit(exc.returncode or 1) from None
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1) from None
