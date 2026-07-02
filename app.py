import json
import os
import subprocess
import sys
import tempfile

import pandas as pd
import streamlit as st

import static_analyzer
from integration.risk_engine import score_findings


st.set_page_config(page_title="通信ログ・危険通信チェック", layout="wide")

st.title("UI操作 × 通信観測可能性チェック")
st.markdown(
    "UI操作ログ・mitmproxy通信ログ・VPN/pcapメタデータを時系列で突合し、"
    "通信の発生原因と観測可能性（observed / metadata_only / not_observed / capture_failed など）を分けて表示します。"
)
st.info(
    "研究方針: mitmproxy regular modeはHTTP/HTTPS本文を読めた場合の詳細解析に使い、"
    "PCAPdroid等のVPN/pcapメタデータを主な通信先観測ログとして併用します。"
    "未観測イベントはLowではなくUnknownとして扱います。"
)

DEFAULT_ALLOWED_DOMAINS = "example.com\napi.example.com"


@st.cache_data(show_spinner=False)
def read_csv_if_exists(path: str):
    if not os.path.exists(path):
        return None
    return pd.read_csv(path)


def ensure_columns(df, defaults):
    for column, default in defaults.items():
        if column not in df.columns:
            df[column] = default
    return df


def overall_risk_label(df):
    if df.empty:
        return "Unknown"
    if (df["risk"] == "High").any():
        return "High"
    if (df["risk"] == "Medium").any():
        return "Medium"
    if (df["risk"] == "Unknown").any():
        return "Unknown"
    return "Low"




st.sidebar.header("APK静的解析")
st.sidebar.caption("APKをアップロードし、Manifest・権限・URL・SDK/API候補を根拠付きで抽出します。")
uploaded_apk = st.sidebar.file_uploader("解析対象APK", type=["apk"])
static_csv_path = st.sidebar.text_input("静的解析CSV", "logs/static_analysis.csv")
static_json_path = st.sidebar.text_input("静的解析JSON", "logs/static_analysis.json")

if uploaded_apk is not None and st.sidebar.button("APKを静的解析する"):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp_apk:
        tmp_apk.write(uploaded_apk.getbuffer())
        tmp_apk_path = tmp_apk.name
    try:
        with st.spinner("APKを静的解析しています..."):
            static_analyzer.analyze_static(tmp_apk_path, static_csv_path, static_json_path)
        st.sidebar.success("静的解析が完了しました。")
        st.cache_data.clear()
        st.rerun()
    except Exception as exc:
        st.sidebar.error("静的解析に失敗しました。")
        st.sidebar.exception(exc)
    finally:
        try:
            os.unlink(tmp_apk_path)
        except OSError:
            pass

st.sidebar.header("ログ再判定")
st.sidebar.caption("PCAPdroid等のVPN/pcap CSVを logs/pcap_metadata.csv に正規化してから、UIログと通信観測ログを対応付けます。")
st.sidebar.code(
    "python normalize_pcap_metadata.py raw_pcapdroid.csv --output logs/pcap_metadata.csv",
    language="bash",
)
traffic_log_path = st.sidebar.text_input("mitmproxy通信ログCSV", "logs/traffic_logs.csv")
metadata_log_path = st.sidebar.text_input("VPN/pcapメタデータCSV（任意）", "logs/pcap_metadata.csv")
risk_result_path = st.sidebar.text_input("判定結果CSV", "logs/risk_results.csv")
target_package = st.sidebar.text_input("対象パッケージ（任意）", "")
allowed_domains_text = st.sidebar.text_area("First-party / allowlistドメイン（1行1件）", DEFAULT_ALLOWED_DOMAINS, height=90)
include_system_probes = st.sidebar.checkbox(
    "Android/Google接続確認通信も含める",
    value=False,
    help="通常はOFF推奨です。generate_204/gen_204はOSの接続確認で、アプリ通信ではないことが多いため除外します。",
)

if st.sidebar.button("通信ログを判定する"):
    command = [
        sys.executable,
        "analyze_logs.py",
        "--traffic-log",
        traffic_log_path,
        "--output",
        risk_result_path,
    ]
    for domain in [line.strip() for line in allowed_domains_text.splitlines() if line.strip()]:
        command.extend(["--allowed-domain", domain])
    if metadata_log_path and os.path.exists(metadata_log_path):
        command.extend(["--metadata-log", metadata_log_path])
    if target_package.strip():
        command.extend(["--target-package", target_package.strip()])
    if include_system_probes:
        command.append("--include-system-probes")

    with st.spinner("通信ログを判定しています..."):
        result = subprocess.run(command, text=True, capture_output=True)

    st.sidebar.code(" ".join(command), language="bash")
    if result.returncode == 0:
        st.sidebar.success("判定が完了しました。")
        st.cache_data.clear()
        st.rerun()
    else:
        st.sidebar.error("判定に失敗しました。")
        st.sidebar.text_area("標準出力", result.stdout, height=160)
        st.sidebar.text_area("エラー", result.stderr, height=160)


if os.path.exists(static_json_path) or os.path.exists(static_csv_path):
    st.header("APK静的解析レポート")
    if os.path.exists(static_json_path):
        with open(static_json_path, encoding="utf-8") as f:
            static_report = json.load(f)
        application = static_report.get("application", {})
        findings = static_report.get("findings", [])
        priority = score_findings(findings)
        app_cols = st.columns(5)
        app_cols[0].metric("パッケージ", application.get("package_name") or "不明")
        app_cols[1].metric("targetSdk", application.get("target_sdk") or "不明")
        app_cols[2].metric("権限数", len(static_report.get("permissions", [])))
        app_cols[3].metric("検出証拠数", len(findings))
        app_cols[4].metric("確認優先度", priority["priority"])
        st.caption("この静的解析は『送信した』とは断定せず、公開前に開発者が確認すべき候補を提示します。")

        overview_tab, evidence_tab, json_tab = st.tabs(["概要", "証拠一覧", "JSON"])
        with overview_tab:
            st.subheader("アプリ基本情報")
            st.json(application)
            st.subheader("権限")
            permissions = pd.DataFrame(static_report.get("permissions", []))
            if not permissions.empty:
                st.dataframe(permissions, width="stretch")
            else:
                st.info("権限は検出されませんでした。")
            st.subheader("コンポーネント要約")
            component_summary = pd.DataFrame.from_dict(static_report.get("component_summary", {}), orient="index")
            if not component_summary.empty:
                st.dataframe(component_summary, width="stretch")
            else:
                st.info("aapt badgingからコンポーネント情報を取得できませんでした。")
            st.subheader("API / SDK候補")
            st.json({
                "sensitive_api_hints": static_report.get("sensitive_api_hints", {}),
                "network_api_hints": static_report.get("network_api_hints", {}),
                "sdk_hints": static_report.get("sdk_hints", {}),
            })
        with evidence_tab:
            evidence_df = pd.DataFrame(findings)
            if not evidence_df.empty:
                st.dataframe(evidence_df, width="stretch")
            else:
                st.info("証拠は検出されませんでした。")
        with json_tab:
            st.download_button(
                "JSONレポートをダウンロード",
                data=json.dumps(static_report, ensure_ascii=False, indent=2),
                file_name="static_analysis.json",
                mime="application/json",
            )
            st.json(static_report)
    else:
        static_df = read_csv_if_exists(static_csv_path)
        if static_df is not None:
            st.dataframe(static_df, width="stretch")

result_file = risk_result_path

if os.path.exists(result_file):
    df = pd.read_csv(result_file)
    df = ensure_columns(
        df,
        {
            "observability_status": "observed",
            "metadata_source": "",
            "destination_ip": "",
            "destination_port": "",
            "protocol": "",
            "bytes_sent": "",
            "bytes_received": "",
            "risk": "Low",
            "risk_category": "未分類通信",
            "risk_rule": "unclassified",
            "domain": "",
            "destination_party": "unknown",
            "scheme": "",
            "traffic_timestamp": "",
            "data_categories": "",
            "content_type": "",
            "request_size": "",
            "response_size": "",
            "duration_ms": "",
            "error": "",
        },
    )
    observed_df = df[df["observability_status"].isin(["observed", "metadata_only"])].copy()
    unreadable_df = df[df["observability_status"].isin(["unreadable_tls", "metadata_only"])].copy()
    not_observed_df = df[df["observability_status"].isin(["not_observed", "capture_failed"])].copy()

    total_traffic = len(observed_df)
    unreadable_count = len(unreadable_df)
    not_observed_count = len(not_observed_df)
    domain_count = observed_df["domain"].replace("", pd.NA).dropna().nunique()
    external_count = len(observed_df[observed_df["destination_party"] == "third-party"])
    http_count = len(observed_df[observed_df["risk_rule"] == "cleartext_http"])
    sensitive_count = len(observed_df[observed_df["risk_rule"] == "sensitive_key"])
    error_count = len(observed_df[observed_df["error"].astype(str).str.len() > 0])

    st.subheader("サマリー")
    summary_source_df = df.copy()
    summary_source_df["metadata_source"] = summary_source_df["metadata_source"].fillna("").replace("", "(none)")
    source_summary = summary_source_df.groupby(["observability_status", "metadata_source"]).size().reset_index(name="count")
    st.caption("observed=mitmproxyで本文/URLまで読めた通信、metadata_only=VPN/pcapで通信先メタデータのみ観測、not_observed/capture_failed=通信なしとは断定しない未観測です。")
    st.dataframe(source_summary, width="stretch")
    cols = st.columns(8)
    cols[0].metric("観測通信数", total_traffic)
    cols[1].metric("本文未読/メタデータ", unreadable_count)
    cols[2].metric("未観測イベント", not_observed_count)
    cols[3].metric("通信先ドメイン数", domain_count)
    cols[4].metric("外部ドメイン通信", external_count)
    cols[5].metric("HTTP平文通信", http_count)
    cols[6].metric("個人情報らしいキー", sensitive_count)
    cols[7].metric("通信エラー", error_count)
    st.metric("総合リスク", overall_risk_label(df))

    summary_tab, details_tab, raw_tab = st.tabs(["リスク内訳", "詳細ログ", "生ログ"])

    with summary_tab:
        col_left, col_right = st.columns(2)
        with col_left:
            st.subheader("リスク分類")
            risk_summary = df.groupby(["risk", "risk_category", "risk_rule"]).size().reset_index(name="count")
            st.dataframe(risk_summary, width="stretch")
        with col_right:
            st.subheader("通信先ドメインランキング")
            domain_summary = (
                observed_df.groupby(["domain", "destination_party"])
                .size()
                .reset_index(name="count")
                .sort_values("count", ascending=False)
            )
            st.dataframe(domain_summary.head(30), width="stretch")

        if not observed_df.empty:
            st.subheader("HTTP/HTTPS 内訳")
            scheme_summary = observed_df.groupby("scheme").size().reset_index(name="count")
            st.bar_chart(scheme_summary, x="scheme", y="count")

    with details_tab:
        st.subheader("判定結果")
        selected_risks = st.multiselect(
            "表示するリスク",
            options=sorted(df["risk"].dropna().unique()),
            default=sorted(df["risk"].dropna().unique()),
        )
        filtered_df = df[df["risk"].isin(selected_risks)] if selected_risks else df

        def color_risk(row):
            if row["risk"] == "High":
                return ["background-color: #f8d7da; color: #721c24; font-weight: bold;"] * len(row)
            if row["risk"] == "Medium":
                return ["background-color: #fff3cd; color: #856404;"] * len(row)
            if row["risk"] == "Unknown" or row.get("observability_status") in {"unreadable_tls", "metadata_only", "not_observed", "capture_failed"}:
                return ["background-color: #e2e3e5; color: #383d41;"] * len(row)
            return ["background-color: #d4edda; color: #155724;"] * len(row)

        display_columns = [
            "traffic_timestamp",
            "observability_status",
            "risk",
            "risk_category",
            "risk_rule",
            "data_categories",
            "domain",
            "destination_party",
            "metadata_source",
            "destination_ip",
            "destination_port",
            "protocol",
            "bytes_sent",
            "bytes_received",
            "scheme",
            "method",
            "status_code",
            "content_type",
            "request_size",
            "response_size",
            "duration_ms",
            "error",
            "reason",
            "url",
        ]
        display_columns = [column for column in display_columns if column in filtered_df.columns]
        st.dataframe(filtered_df[display_columns].style.apply(color_risk, axis=1), width="stretch")

    with raw_tab:
        st.subheader("通信ログ")
        traffic_df = read_csv_if_exists(traffic_log_path)
        if traffic_df is not None:
            st.dataframe(traffic_df, width="stretch")
        else:
            st.info(f"{traffic_log_path} が見つかりません。")

        st.subheader("VPN/pcapメタデータ")
        metadata_df = read_csv_if_exists(metadata_log_path)
        if metadata_df is not None:
            st.dataframe(metadata_df, width="stretch")
        else:
            st.info(f"{metadata_log_path} が見つかりません。")
else:
    st.info("判定結果CSVがまだ生成されていません。サイドバーから通信ログを判定してください。")
