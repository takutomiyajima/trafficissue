"""Compatibility wrapper for the MVP static APK analyzer."""
from static_analyzer import analyze_static, build_json_report, categorize_permission, parse_components

__all__ = ["analyze_static", "build_json_report", "categorize_permission", "parse_components"]
