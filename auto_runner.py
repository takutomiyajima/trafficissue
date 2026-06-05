import uiautomator2 as u2
import time
import csv
import os
import datetime

def main():
    d = u2.connect() 
    
    filepath = "logs/ui_events.csv"
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    # ログ初期化
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["event_id", "timestamp", "screen", "action", "element_text"])

    package_name = "com.example.rikoten_pamphlet_2025" 
    print(f"[UI] Starting app: {package_name}")
    d.app_start(package_name)
    time.sleep(5)  # 画面が完全にロードされるまで少し長めに待つ

    event_counter = 1

    # --- パターン1: XMLに名前が明記されているボタン（description指定） ---
    named_buttons = [
        "Get Ticket", 
        "Ticket List", 
        "Restaurant Collab", 
        "Walkrally", 
        "Survey"
    ]

    for btn_desc in named_buttons:
        # text="..." ではなく description="..." で指定する
        el = d(description=btn_desc)
        if el.exists:
            timestamp = int(datetime.datetime.now().timestamp())
            el.click()
            
            with open(filepath, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([f"E{event_counter:03d}", timestamp, "Home", "tap", btn_desc])
            
            print(f"[UI] Clicked '{btn_desc}' at {timestamp}")
            event_counter += 1
            time.sleep(5) # 通信発生を待つバッファ
        else:
            print(f"[UI] Button '{btn_desc}' not found on screen.")

    # --- パターン2: 上部の名前なしタブボタン（XMLのboundsから計算した座標指定） ---
    # XMLの [66,282][203,419] などの中心点を計算した座標です
    tab_coordinates = [
        {"name": "TopTab_1", "x": 134, "y": 350},
        {"name": "TopTab_2", "x": 337, "y": 350},
        {"name": "TopTab_3", "x": 540, "y": 350},
        {"name": "TopTab_4", "x": 743, "y": 350},
        {"name": "TopTab_5", "x": 945, "y": 350},
    ]

    print("[UI] Clicking top row tab buttons by coordinates...")
    for tab in tab_coordinates:
        timestamp = int(datetime.datetime.now().timestamp())
        
        # 座標で直接タップ
        d.click(tab["x"], tab["y"])
        
        with open(filepath, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([f"E{event_counter:03d}", timestamp, "Home", "tap", tab["name"]])
        
        print(f"[UI] Position Clicked '{tab['name']}' ({tab['x']}, {tab['y']}) at {timestamp}")
        event_counter += 1
        time.sleep(5)

    print("[UI] Automation test finished.")

if __name__ == "__main__":
    main()