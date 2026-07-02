# trafficissue

UI操作ログと通信観測ログを時刻で対応付け、Androidアプリの「どの操作の後に、どの通信先が、どの程度観測できたか」を整理するためのMVPです。

## 研究方針

この版では、mitmproxy regular modeを全通信取得の主役にしません。一般APKではOSプロキシを使わない通信、証明書信頼の問題、証明書ピンニング、HTTP/3/QUICなどにより、HTTPプロキシだけではアプリ内通信が観測できないことがあります。

そのため、役割を次のように分けます。

| 取得方法 | 役割 | 出力での扱い |
| --- | --- | --- |
| UI auto runner | 操作時刻・画面・タップ対象を記録 | `logs/ui_events.csv` |
| PCAPdroid / VPN / pcap | 通信時刻、宛先ドメイン/IP、ポート、プロトコル、通信量、アプリ名を取得 | `logs/pcap_metadata.csv` / `metadata_only` |
| mitmproxy regular mode | 取れたHTTP/HTTPSだけ本文・URL・メソッド等を詳細解析 | `logs/traffic_logs.csv` / `observed` |
| 静的解析 | 権限・URL・SDK候補を補助的に確認 | `logs/static_analysis.csv` |

重要な前提として、通信が見えないイベントは「安全」ではありません。`not_observed` / `capture_failed` として `Unknown` にし、Lowには落としません。

## 最短の実験手順

1. PCAPdroidなどのVPN型キャプチャで対象アプリを指定して記録します。
2. `auto_runner.py` または手動操作でUIイベントを `logs/ui_events.csv` に残します。
3. PCAPdroidのCSVを書き出し、解析用メタデータCSVに正規化します。
4. `analyze_logs.py` でUIイベントと通信観測ログを時刻で対応付けます。
5. Streamlit画面または `logs/risk_results.csv` で `observability_status` と通信先を確認します。

```bash
python normalize_pcap_metadata.py raw_pcapdroid.csv --output logs/pcap_metadata.csv
python analyze_logs.py \
  --ui-log logs/ui_events.csv \
  --traffic-log logs/traffic_logs.csv \
  --metadata-log logs/pcap_metadata.csv \
  --output logs/risk_results.csv \
  --target-package com.example.app
streamlit run app.py
```

## `logs/pcap_metadata.csv` の形式

`normalize_pcap_metadata.py` は、PCAPdroid/VPN CSVの代表的な列名を次の解析用形式にそろえます。

| column | 内容 |
| --- | --- |
| `timestamp` | epoch秒。UIイベントとの対応付けに使います。 |
| `package` | Androidパッケージ名。対象アプリで絞り込めます。 |
| `destination_host` | 宛先ドメイン、SNI、ホスト名など。 |
| `destination_ip` | 宛先IP。ドメインが取れない場合も残します。 |
| `destination_port` | 宛先ポート。 |
| `protocol` | TCP/UDP等。 |
| `bytes_sent` | 送信バイト数。 |
| `bytes_received` | 受信バイト数。 |
| `source` | `pcapdroid` などの取得元。 |

## 中間発表向けの整理

- 評価APKでmitmproxy regular modeを試したが、アプリ内通信が `traffic_logs.csv` に入らないケースがあった。
- この結果から、一般APKではHTTPプロキシ方式だけでは通信観測が不十分だと判断した。
- 本システムでは、未観測をLowにせず `Unknown` / `not_observed` / `capture_failed` として扱う。
- 今後はVPN/pcap型通信取得と静的解析を組み合わせ、通信本文ではなく通信先メタデータとUI操作の対応付けを中心に進める。
- mitmproxyは、取れた通信を詳細解析する補助として利用する。

## APK静的解析MVP

添付資料の「Androidアプリ公開前プライバシー確認支援システム」に対応する最小構成として、APKの静的解析レポート生成を追加しています。目的は危険アプリの断定ではなく、公開前に開発者が確認すべき候補を根拠付きで提示することです。

```bash
python static_analyzer.py path/to/app.apk \
  --output logs/static_analysis.csv \
  --json-output logs/static_analysis.json
streamlit run app.py
```

静的解析では、現時点で次を抽出します。

| 項目 | 内容 |
| --- | --- |
| APK基本情報 | SHA-256、ファイルサイズ、パッケージ名、バージョン、SDK、debuggable |
| Manifest候補 | 権限、コンポーネント、exported / permission保護の有無 |
| プライバシー候補 | センシティブ権限カテゴリ、位置情報・連絡先・端末IDなどのAPI文字列ヒント |
| 通信候補 | URL、ドメイン、HTTP/WebView/Socket API文字列ヒント、network_security_config |
| SDK候補 | Firebase、Google Ads、Google Maps等の文字列・パッケージヒント |

設定ファイルは `config/` に分離しており、研究中に検出対象を増やしやすい構成にしています。軽量MVPのため、現段階ではaapt/aapt2とAPK内文字列を中心に解析します。本文送信や実行時挙動は断定せず、動的解析ログと組み合わせて確認優先度を上げる設計です。
