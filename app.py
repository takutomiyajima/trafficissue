import os
import subprocess
import sys

import pandas as pd
import streamlit as st


st.set_page_config(page_title="通信ログ・危険通信チェック", layout="wide")

st.title("通信ログ・危険通信チェック")
st.markdown(
    "mitmproxyで記録した `logs/traffic_logs.csv` を読み込み、HTTP平文通信、個人情報らしいURLキー、"
    "広告/解析系ドメイン、許可外ドメインへの送信、通信エラーなどの分かりやすいルールだけで判定します。"
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
    observed = df[df["observability_status"] == "observed"] if "observability_status" in df.columns else df
    if not observed.empty:
        if (observed["risk"] == "High").any():
            return "High"
        if (observed["risk"] == "Medium").any():
            return "Medium"
        return "Low"
    if "observability_status" in df.columns and (df["observability_status"] == "unreadable").any():
        return "Unknown"
    return "Low"


st.sidebar.header("ログ再判定")
st.sidebar.caption("APK自動操作などの複雑な操作は置かず、既に取れている通信ログを確認・判定します。")
traffic_log_path = st.sidebar.text_input("通信ログCSV", "logs/traffic_logs.csv")
risk_result_path = st.sidebar.text_input("判定結果CSV", "logs/risk_results.csv")
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

result_file = risk_result_path

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
            "data_categories": "",
            "content_type": "",
            "request_size": "",
            "response_size": "",
            "duration_ms": "",
            "error": "",
        },
    )
    observed_df = df[df["observability_status"] == "observed"].copy()
    unreadable_df = df[df["observability_status"] == "unreadable"].copy()

    total_traffic = len(observed_df)
    unreadable_count = len(unreadable_df)
    domain_count = observed_df["domain"].replace("", pd.NA).dropna().nunique()
    external_count = len(observed_df[observed_df["destination_party"] == "third-party"])
    http_count = len(observed_df[observed_df["risk_rule"] == "cleartext_http"])
    sensitive_count = len(observed_df[observed_df["risk_rule"] == "sensitive_key"])
    error_count = len(observed_df[observed_df["error"].astype(str).str.len() > 0])

    st.subheader("サマリー")
    cols = st.columns(7)
    cols[0].metric("判定済み通信数", total_traffic)
    cols[1].metric("判定不能通信", unreadable_count)
    cols[2].metric("通信先ドメイン数", domain_count)
    cols[3].metric("外部ドメイン通信", external_count)
    cols[4].metric("HTTP平文通信", http_count)
    cols[5].metric("個人情報らしいキー", sensitive_count)
    cols[6].metric("通信エラー", error_count)
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
            if row["risk"] == "Unknown" or row.get("observability_status") == "unreadable":
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
else:
    st.info("判定結果CSVがまだ生成されていません。サイドバーから通信ログを判定してください。")
