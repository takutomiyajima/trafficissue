import streamlit as st
import pandas as pd
import os
import subprocess
import sys

st.set_page_config(page_title="Android UI-Traffic Risk Analyzer", layout="wide")

st.title("📱 Android UI操作起因 通信リスク検知システム")
st.markdown("自動操作ログと通信ログを時系列で対応づけ、危険な挙動のトリガーとなったUI要素を特定します。")


st.sidebar.header("🚀 APK自動解析")
st.sidebar.markdown(
    "APKをアップロードすると、インストール、アプリ起動、UI自動探索、通信ログとの突合解析までを一括実行できます。"
)
uploaded_apk = st.sidebar.file_uploader("解析するAPKファイル", type=["apk"])
max_events = st.sidebar.number_input("最大タップ数", min_value=1, max_value=200, value=30, step=1)
wait_seconds = st.sidebar.number_input("各操作後の待機秒数", min_value=1, max_value=60, value=5, step=1)
skip_capture = st.sidebar.checkbox("mitmproxyを起動せず既存の通信ログを使う", value=False)

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
        ]
        if skip_capture:
            command.append("--skip-capture")

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
    
    # 統計サマリー
    col1, col2, col3 = st.columns(3)
    col1.metric("トリガーされたUI操作数", len(df['event_id'].unique()))
    col2.metric("⚠️ High リスク (HTTP等)", len(df[df['risk'] == 'High']))
    col3.metric("🔔 Middle リスク (外部送信等)", len(df[df['risk'] == 'Middle']))
    
    st.write("---")
    st.subheader("🔍 判定結果（タイムスタンプ突合）")
    
    # 行の色分けルール
    def color_risk(row):
        styles = [''] * len(row)
        if row['risk'] == 'High':
            return ['background-color: #f8d7da; color: #721c24; font-weight: bold;'] * len(row)
        elif row['risk'] == 'Middle':
            return ['background-color: #fff3cd; color: #856404;'] * len(row)
        return ['background-color: #d4edda; color: #155724;'] * len(row)
        
    styled_df = df.style.apply(color_risk, axis=1)
    st.dataframe(styled_df, use_container_width=True)
    
    # 各種生データログの確認用タブ
    st.write("---")
    st.subheader("📊 各コンポーネントの生データ")
    tab1, tab2 = st.tabs(["UI操作イベントログ (CSV)", "通信パケットログ (CSV)"])
    
    with tab1:
        if os.path.exists("logs/ui_events.csv"):
            st.dataframe(pd.read_csv("logs/ui_events.csv"), use_container_width=True)
    with tab2:
        if os.path.exists("logs/traffic_logs.csv"):
            st.dataframe(pd.read_csv("logs/traffic_logs.csv"), use_container_width=True)
else:
    st.info("解析結果（logs/risk_results.csv）がまだ生成されていません。上のステップを実行してください。")