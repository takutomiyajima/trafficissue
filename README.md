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
  --target-package com.example.app \
  --static-report logs/static_analysis.json \
  --integrated-output logs/integrated_analysis.json
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

設定ファイルは `config/` に分離しており、権限カテゴリ、センシティブAPI、通信API、SDK署名をコード変更なしで追加できます。CLIでは別のルールセットを `--config-dir` で指定できます。`run_analysis.py` から実行した場合もCSVとJSONの両方が同じログディレクトリに生成されます。

```bash
python static_analyzer.py path/to/app.apk --config-dir config
```

軽量構成のため、現段階ではaapt/aapt2・apkanalyzerとAPKメンバーごとの文字列を中心に解析します。検出したAPIは実呼び出しではなく文字列証拠であり、権限の宣言状況に応じて確度を付けます。本文送信や実行時挙動は断定せず、動的解析ログと組み合わせて確認優先度を上げる設計です。解析ツールの一部が利用できない場合は、JSONの `analysis_status` と `stages` に部分成功と失敗理由を残します。

JSONには、動的解析が読み込みやすいバージョン付きの `dynamic_analysis_handoff` を出力します。ここには対象パッケージ、静的に見つかった通信先・URL、センシティブデータカテゴリ、SDK IDを正規化して格納します。`analyze_logs.py --static-report` で読み込むと、動的に観測した各通信へ `static_match`、`static_evidence`、`static_app_data_categories` が追加されます。最後の列はアプリ全体の静的候補であり、その通信先へ実際に送信したデータを意味しません。`run_analysis.py` ではこの連携を自動的に行います。

## 静的・動的解析の統合レポート

`analyze_logs.py` は従来の通信行ベースの `risk_results.csv` に加え、既定で `logs/integrated_analysis.json` を生成します。一括実行の `run_analysis.py` でも同じログディレクトリへ生成されます。このJSONでは、取得した事実を `observations`、判断根拠を `evidence`、開発者が確認する候補を `findings` として分離しています。

| 状態 | 意味 |
| --- | --- |
| `Confirmed` | 動的解析で通信または実行時挙動を確認したが、対応する静的候補はない |
| `Potential` | 静的解析には実装候補があるが、今回の動的解析では実行を確認していない |
| `Supported` | 静的候補と動的観測の両方に、同じ通信先またはデータカテゴリの根拠がある |
| `Unverified` | 通信取得失敗、本文未取得、操作範囲不足などにより確認できない |

`confidence` は根拠の確からしさ、`review_priority` は開発者が確認する順序であり、別々に出力します。いずれの状態も開発意図との一致を自動判定するものではありません。各findingの `review_question` に沿って、開発者自身が仕様と照合することを前提としています。

### 現時点の既知の制約

詳細な項目別判定、残る問題、研究としての改善優先順位は [`docs/limitations_assessment.md`](docs/limitations_assessment.md) にまとめています。

- API検出は実際の呼び出しを逆解析した結果ではなく、APK内のクラス文字列を根拠にした候補です。汎用的なメソッド名だけでは検出せず、宣言クラスが同時に存在する場合だけ候補にしますが、未使用ライブラリによる偽陽性は残ります。
- `static_match=true` は「静的・動的の両方で同じ通信先が見つかった」ことだけを示し、センシティブデータの送信を証明しません。
- 証明書ピンニング、QUIC、独自暗号化などにより、mitmproxyで本文を取得できない通信があります。VPN/pcapメタデータと併用し、未観測を安全判定に使わないでください。
- 内蔵YAMLローダーが対応するのは、このリポジトリの設定ファイルで使用している限定的なYAML構文だけです。

### エラーの確認方法

静的解析CLIのエラーは `stage`、APKパス、元の例外型を標準エラーへ表示します。主なstageは `input_validation`、`config_loading`、`manifest_analysis`、`apk_metadata`、`apk_string_extraction`、`csv_report_write`、`json_report_write` です。動的解析で静的JSONを読み込めなかった場合も、`file_read`、`json_parse`、`schema_validation` のいずれで失敗したかと対象ファイルを表示します。JSON構文エラーには行番号と列番号も含まれます。

### 実APKを使った結合テスト

手元のAPKをリポジトリへコミットせずに、ファイル読み込みからCSV・JSON生成までを結合テストできます。APKのパスを環境変数で渡してください。テストはAPKがZIP形式であり、`AndroidManifest.xml` を含むことも確認します。

```bash
TRAFFICISSUE_TEST_APK=/absolute/path/to/app.apk \
  python -m unittest tests.test_static_analyzer_real_apk -v
```

環境変数を設定しない通常のテスト実行では、この結合テストだけがskipされます。実APKに個人情報や秘密情報が含まれる可能性があるため、テスト用APK自体はリポジトリに追加しません。
