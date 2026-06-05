import streamlit as st
import pandas as pd
import os

st.set_page_config(page_title="Android UI-Traffic Risk Analyzer", layout="wide")

st.title("📱 Android UI操作起因 通信リスク検知システム")
st.markdown("自動操作ログと通信ログを時系列で対応づけ、危険な挙動のトリガーとなったUI要素を特定します。")

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