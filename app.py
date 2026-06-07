import os
import subprocess
import sys

import pandas as pd
import streamlit as st


st.set_page_config(page_title="Android通信ログ・プライバシーリスク可視化", layout="wide")

st.title("📱 Androidアプリ通信ログ・プライバシーリスク可視化")
st.markdown(
    "APKをエミュレータ/端末上で自動操作し、mitmproxyで取得した通信ログをもとに、"
    "通信先・通信方式・URLキー・発生タイミングからルールベースでリスク分類します。"
)


st.sidebar.header("🚀 APK自動解析")
st.sidebar.markdown("APKをアップロードすると、UI自動操作、通信ログ収集、リスク分類までを実行します。")
uploaded_apk = st.sidebar.file_uploader("解析するAPKファイル", type=["apk"])
max_events = st.sidebar.number_input("最大タップ数", min_value=1, max_value=200, value=30, step=1)
wait_seconds = st.sidebar.number_input("各操作後の待機秒数", min_value=1, max_value=60, value=5, step=1)
window_seconds = st.sidebar.number_input("UI操作と通信を紐付ける秒数", min_value=1.0, max_value=60.0, value=5.0, step=0.5)
allowed_domains_text = st.sidebar.text_area("First-party / allowlistドメイン（1行1件）", "example.com\napi.example.com", height=90)
skip_capture = st.sidebar.checkbox("mitmproxyを起動せず既存の通信ログを使う", value=False)
skip_proxy_setup = st.sidebar.checkbox("Androidのプロキシ設定を変更しない", value=False)
proxy_host = st.sidebar.text_input("Android端末から見たmitmproxyホスト（空なら自動）", "")
no_adb_reverse = st.sidebar.checkbox("adb reverseを使わずホストIPへ接続する", value=False)
include_system_probes = st.sidebar.checkbox(
    "Android/Google接続確認通信も結果に含める",
    value=False,
    help="通常はOFF推奨です。generate_204/gen_204はOSの接続確認で、アプリ操作起因ではないことが多いため除外します。",
)


def ensure_columns(df, defaults):
    for column, default in defaults.items():
        if column not in df.columns:
            df[column] = default
    return df


def overall_risk_label(df):
    observed = df[df["observability_status"] == "observed"] if "observability_status" in df.columns else df
    if observed.empty:
        return "Low"
    if (observed["risk"] == "High").any():
        return "High"
    if (observed["risk"] == "Medium").any():
        return "Medium"
    return "Low"


if uploaded_apk is not None:
    os.makedirs("uploads", exist_ok=True)
    apk_path = os.path.join("uploads", uploaded_apk.name)
    with open(apk_path, "wb") as f:
        f.write(uploaded_apk.getbuffer())
    st.sidebar.success(f"APKを保存しました: {apk_path}")

    if st.sidebar.button("APKから自動解析を開始"):
        command = [
            sys.executable,
            "run_analysis.py",
            apk_path,
            "--max-events",
            str(max_events),
            "--wait",
            str(wait_seconds),
            "--window",
            str(window_seconds),
        ]
        for domain in [line.strip() for line in allowed_domains_text.splitlines() if line.strip()]:
            command.extend(["--allowed-domain", domain])
        if skip_capture:
            command.append("--skip-capture")
        if skip_proxy_setup:
            command.append("--skip-proxy-setup")
        if proxy_host.strip():
            command.extend(["--proxy-host", proxy_host.strip()])
        if no_adb_reverse:
            command.append("--no-adb-reverse")
        if include_system_probes:
            command.append("--include-system-probes")

        with st.spinner("APK解析を実行中です。接続済みAndroid端末/エミュレータを操作します..."):
            result = subprocess.run(command, text=True, capture_output=True)

        st.sidebar.code(" ".join(command), language="bash")
        if result.returncode == 0:
            st.sidebar.success("解析が完了しました。")
            if result.stdout:
                st.sidebar.text_area("実行ログ", result.stdout, height=240)
            st.rerun()
        else:
            st.sidebar.error("解析に失敗しました。")
            st.sidebar.text_area("標準出力", result.stdout, height=160)
            st.sidebar.text_area("エラー", result.stderr, height=160)

result_file = "logs/risk_results.csv"

if os.path.exists(result_file):
    df = pd.read_csv(result_file)
    df = ensure_columns(
        df,
        {
            "observability_status": "observed",
            "risk": "Low",
            "risk_category": "未分類通信",
            "risk_rule": "unclassified",
            "domain": "",
            "destination_party": "unknown",
            "scheme": "",
            "traffic_timestamp": "",
            "time_delta": "",
            "data_categories": "",
            "content_type": "",
            "request_size": "",
            "response_size": "",
        },
    )
    observed_df = df[df["observability_status"] == "observed"].copy()

    total_traffic = len(observed_df)
    domain_count = observed_df["domain"].replace("", pd.NA).dropna().nunique()
    external_count = len(observed_df[observed_df["destination_party"] == "third-party"])
    tracker_count = len(observed_df[observed_df["risk_rule"] == "tracker_domain"])
    http_count = len(observed_df[observed_df["risk_rule"] == "cleartext_http"])
    sensitive_count = len(observed_df[observed_df["risk_rule"] == "sensitive_key"])

    st.subheader("📌 MVPサマリー")
    cols = st.columns(6)
    cols[0].metric("総通信数", total_traffic)
    cols[1].metric("通信先ドメイン数", domain_count)
    cols[2].metric("外部ドメイン通信", external_count)
    cols[3].metric("広告・解析系通信", tracker_count)
    cols[4].metric("HTTP平文通信", http_count)
    cols[5].metric("個人情報らしいキー", sensitive_count)
    st.metric("総合リスク", overall_risk_label(df))

    summary_tab, timeline_tab, details_tab, raw_tab = st.tabs(["リスク内訳", "時系列", "詳細ログ", "生ログ"])

    with summary_tab:
        col_left, col_right = st.columns(2)
        with col_left:
            st.subheader("🏷️ リスク分類")
            risk_summary = df.groupby(["risk", "risk_category", "risk_rule"]).size().reset_index(name="count")
            st.dataframe(risk_summary, width="stretch")
        with col_right:
            st.subheader("🌐 通信先ドメインランキング")
            domain_summary = (
                observed_df.groupby(["domain", "destination_party"])
                .size()
                .reset_index(name="count")
                .sort_values("count", ascending=False)
            )
            st.dataframe(domain_summary.head(30), width="stretch")

        if not observed_df.empty:
            st.subheader("📊 HTTP/HTTPS 内訳")
            scheme_summary = observed_df.groupby("scheme").size().reset_index(name="count")
            st.bar_chart(scheme_summary, x="scheme", y="count")

    with timeline_tab:
        st.subheader("🕒 操作イベントと通信発生タイミング")
        timeline_df = observed_df.copy()
        if not timeline_df.empty:
            timeline_df["traffic_timestamp"] = pd.to_numeric(timeline_df["traffic_timestamp"], errors="coerce")
            st.scatter_chart(timeline_df, x="traffic_timestamp", y="time_delta", color="risk")
        else:
            st.info("通信イベントは観測されていません。")

    with details_tab:
        st.subheader("🔍 ルールベース判定結果")
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
            return ["background-color: #d4edda; color: #155724;"] * len(row)

        display_columns = [
            "event_id",
            "time_delta",
            "risk",
            "risk_category",
            "risk_rule",
            "data_categories",
            "domain",
            "destination_party",
            "scheme",
            "method",
            "status_code",
            "content_type",
            "request_size",
            "response_size",
            "reason",
            "url",
        ]
        display_columns = [column for column in display_columns if column in filtered_df.columns]
        st.dataframe(filtered_df[display_columns].style.apply(color_risk, axis=1), width="stretch")

    with raw_tab:
        st.subheader("📄 生ログ")
        tab1, tab2 = st.tabs(["UI操作イベントログ", "通信ログ"])
        with tab1:
            if os.path.exists("logs/ui_events.csv"):
                st.dataframe(pd.read_csv("logs/ui_events.csv"), width="stretch")
        with tab2:
            if os.path.exists("logs/traffic_logs.csv"):
                st.dataframe(pd.read_csv("logs/traffic_logs.csv"), width="stretch")
else:
    st.info("解析結果（logs/risk_results.csv）がまだ生成されていません。APK解析を実行してください。")
