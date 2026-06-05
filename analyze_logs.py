import pandas as pd
import os

def analyze():
    ui_path = "logs/ui_events.csv"
    traffic_path = "logs/traffic_logs.csv"
    output_path = "logs/risk_results.csv"
    
    if not os.path.exists(ui_path) or not os.path.exists(traffic_path):
        print("[Error] Logs not found. Please run capture and runner first.")
        return

    ui_df = pd.read_csv(ui_path)
    traffic_df = pd.read_csv(traffic_path)
    
    results = []
    
    for _, ui_row in ui_df.iterrows():
        ui_time = ui_row['timestamp']
        
        # 条件：ボタンを押した瞬間（ui_time）から5秒以内の通信を抽出
        matched_traffic = traffic_df[
            (traffic_df['timestamp'] >= ui_time) & 
            (traffic_df['timestamp'] <= ui_time + 5)
        ]
        
        if matched_traffic.empty:
            results.append({
                "event_id": ui_row['event_id'],
                "element_text": ui_row['element_text'],
                "domain": "None",
                "scheme": "None",
                "delta_time": 0,
                "risk": "Low",
                "reason": "この操作の直後に通信は検知されませんでした。"
            })
        else:
            for _, t_row in matched_traffic.iterrows():
                delta = t_row['timestamp'] - ui_time
                risk = "Low"
                reason = "暗号化された通常の通信、または既知のドメインです。"
                
                # Rule 1: HTTP通信の検知
                if t_row['scheme'] == 'http':
                    risk = "High"
                    reason = "ボタン押下直後に暗号化されていないHTTP通信が発生しました（盗聴リスク）。"
                
                # Rule 2 & 3: 位置情報や外部ドメインの簡易判定
                elif "maps.googleapis.com" in t_row['domain'] and "Location" in ui_row['element_text']:
                    risk = "Middle"
                    reason = "位置情報関連の操作直後に外部地図APIへの通信を検知。位置情報送信の可能性があります。"
                
                elif "example.com" not in t_row['domain'] and t_row['scheme'] == 'https':
                    risk = "Middle"
                    reason = "サードパーティ、または広告・トラッカー等の外部ドメインへの通信を検知しました。"
                
                results.append({
                    "event_id": ui_row['event_id'],
                    "element_text": ui_row['element_text'],
                    "domain": t_row['domain'],
                    "scheme": t_row['scheme'],
                    "delta_time": f"{delta}s",
                    "risk": risk,
                    "reason": reason
                })
                
    res_df = pd.DataFrame(results)
    res_df.to_csv(output_path, index=False)
    print(f"[Analyzer] Analysis complete. Saved to {output_path}")

if __name__ == "__main__":
    analyze()