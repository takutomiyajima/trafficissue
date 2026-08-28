# trafficissue 利用ガイド

## 1. このシステムでできること

本システムはAndroid APKについて、次の情報を組み合わせ、公開前に開発者が確認すべき候補を提示します。

1. APKの権限、コンポーネント、URL、SDK、API文字列候補を調べる静的解析
2. UI自動操作の時刻と操作内容の記録
3. mitmproxyで取得できたHTTP/HTTPS通信の詳細記録
4. PCAPdroidなどで取得したVPN/pcap通信メタデータの記録
5. UI操作と通信を時刻で対応付ける動的ログ解析
6. 静的・動的解析を統合した開発者レビュー用レポートの生成

本システムは、アプリの安全性や開発意図との一致を自動判定するものではありません。観測できた事実と静的候補を整理し、開発者自身が仕様と比較するための支援システムです。

## 2. 必要なもの

### 必須

- Python 3.10以降
- `pandas`
- Android SDK Platform Toolsの`adb`
- 解析対象のAPK
- USBデバッグまたはAndroid EmulatorでADB接続できる端末

### 使用する機能に応じて必要

| 機能 | 必要なもの |
| --- | --- |
| mitmproxy通信取得 | `mitmproxy` / `mitmdump` |
| 画面表示 | `streamlit` |
| Manifest基本情報 | Android Build Toolsの`aapt`または`aapt2` |
| Manifest XML・コンポーネント詳細 | Android Command-line Toolsの`apkanalyzer` |
| VPN/pcapメタデータ | PCAPdroidなどの取得アプリと、そのCSV出力 |

Pythonパッケージの導入例です。

```bash
python -m pip install pandas mitmproxy streamlit
```

Android SDKを使う場合は、`adb`、`aapt`または`aapt2`、`apkanalyzer`へPATHを通すか、`ANDROID_HOME` / `ANDROID_SDK_ROOT`を設定してください。静的解析ツールの一部がなくても文字列解析は実行されますが、結果は`partial`になり、取得できるManifest情報が減ります。

ADB接続は次のコマンドで確認できます。

```bash
adb devices
```

複数端末が表示される場合は、以降の一括解析で`--serial`を指定します。

## 3. 最も簡単な使い方：一括解析

APKの静的解析、インストール、mitmproxy起動、プロキシ設定、UI自動操作、通信解析、統合レポート生成をまとめて行います。

```bash
python run_analysis.py path/to/app.apk \
  --package com.example.app \
  --allowed-domain example.com \
  --log-dir logs/experiment-001
```

パッケージ名をAPKから取得できる場合、`--package`は省略できます。複数端末がある場合は次のように指定します。

```bash
python run_analysis.py path/to/app.apk \
  --serial emulator-5554 \
  --package com.example.app \
  --max-events 30 \
  --wait 5 \
  --window 5 \
  --log-dir logs/experiment-001
```

主なオプションは次のとおりです。

| オプション | 内容 |
| --- | --- |
| `--serial` | 対象ADB端末のserial |
| `--package` | 対象Androidパッケージ名 |
| `--max-events` | UI自動操作の最大タップ数 |
| `--wait` | 起動後・操作後の待機秒数 |
| `--window` | UI操作後に通信を対応付ける秒数 |
| `--allowed-domain` | first-partyとして扱うドメイン。複数回指定可能 |
| `--listen-port` | mitmproxyの待受ポート。既定は`8082` |
| `--log-dir` | 1回の実験結果を保存するディレクトリ |
| `--metadata-log` | 既存のVPN/pcapメタデータCSV |
| `--skip-static` | 静的解析を省略 |
| `--skip-capture` | mitmproxyを起動せず既存ログを利用 |
| `--skip-proxy-setup` | Androidのglobal HTTP proxyを変更しない |
| `--no-adb-reverse` | adb reverseを使わない |

研究実験では、過去のログを上書きしないよう、実行ごとに異なる`--log-dir`を指定してください。

## 4. 段階ごとに実行する方法

一括解析で問題が起きた場合や、Wireshark・PCAPdroidと比較する場合は、以下の処理を個別に実行します。

### 4.1 APK静的解析

```bash
python static_analyzer.py path/to/app.apk \
  --output logs/static_analysis.csv \
  --json-output logs/static_analysis.json \
  --config-dir config
```

出力:

- `static_analysis.csv`: 権限、URL、ドメイン、SDK、API候補の一覧
- `static_analysis.json`: APK基本情報、解析stage、Manifest情報、静的・動的受け渡し情報

`analysis_status=partial`の場合は、JSONの`stages`を確認します。例えば`manifest_badging_analysis`がfailedなら`aapt/aapt2`、`manifest_xml_analysis`がfailedなら`apkanalyzer`の導入状況を確認してください。

### 4.2 UI自動操作

```bash
python auto_runner.py --apk path/to/app.apk \
  --package com.example.app \
  --max-events 30 \
  --wait 5 \
  --log logs/ui_events.csv
```

利用可能な正確なオプションは次で確認してください。

```bash
python auto_runner.py --help
```

自動操作ではWebView、Canvas、ジェスチャー、CAPTCHA、外部ログインなどを網羅できません。必要な機能は手動で操作し、その操作時刻が`ui_events.csv`へ記録されていることを確認してください。

### 4.3 mitmproxy通信取得

`capture_traffic.py`はmitmproxy addonとして使用します。

```bash
mitmdump \
  -s capture_traffic.py \
  --listen-host 0.0.0.0 \
  --listen-port 8082 \
  --set block_global=false
```

端末からプロキシへ到達できるよう、adb reverseを使用する例です。

```bash
adb reverse tcp:8082 tcp:8082
adb shell settings put global http_proxy 127.0.0.1:8082
```

解析終了後はプロキシを解除します。

```bash
adb shell settings put global http_proxy :0
adb reverse --remove tcp:8082
```

mitmproxyに通信が入らなくても「通信なし」とは判断できません。証明書ピンニング、HTTP/3/QUIC、プロキシを使わない通信などがあるため、次のVPN/pcapメタデータと併用してください。

### 4.4 PCAPdroid CSVの正規化

PCAPdroidなどで対象パッケージを指定して取得したCSVを、解析用の共通形式へ変換します。

```bash
python normalize_pcap_metadata.py raw_pcapdroid.csv \
  --output logs/pcap_metadata.csv
```

最低限、時刻、対象package、宛先hostまたはIPが正しく変換されていることを確認してください。

### 4.5 UI・通信・静的結果の統合

```bash
python analyze_logs.py \
  --ui-log logs/ui_events.csv \
  --traffic-log logs/traffic_logs.csv \
  --metadata-log logs/pcap_metadata.csv \
  --static-report logs/static_analysis.json \
  --target-package com.example.app \
  --allowed-domain example.com \
  --window 5 \
  --output logs/risk_results.csv \
  --integrated-output logs/integrated_analysis.json
```

`--allowed-domain`は自社・開発者管理のドメインだけを指定します。複数ある場合は繰り返します。

```bash
--allowed-domain example.com \
--allowed-domain api.example.jp
```

Androidのconnectivity checkは既定で除外されます。比較実験で含めたい場合だけ`--include-system-probes`を指定します。

## 5. 出力ファイルの読み方

| ファイル | 内容 |
| --- | --- |
| `ui_events.csv` | UIイベント、画面、操作時刻、要素テキスト |
| `traffic_logs.csv` | mitmproxyで詳細取得できた通信 |
| `pcap_metadata.csv` | VPN/pcapで確認した通信先メタデータ |
| `static_analysis.csv` | 静的解析の候補一覧 |
| `static_analysis.json` | 静的解析の構造化レポートと動的解析へのhandoff |
| `risk_results.csv` | UIイベントと通信を時刻で対応付けた行ベース結果 |
| `integrated_analysis.json` | Observation、Evidence、Findingを分離した統合結果 |
| `mitmdump.log` | mitmproxyプロセスの診断ログ |

### 5.1 `observability_status`

| 値 | 意味 |
| --- | --- |
| `observed` | mitmproxyでHTTP/HTTPS情報を取得できた |
| `tunnel_only` | HTTPS CONNECT先は取得できたが、TLS内部のHTTPリクエストは取得できない |
| `metadata_only` | VPN/pcapで通信先は分かったが、HTTP本文は読めない |
| `unreadable_tls` | 通信を観測したが、方式または通信先が不完全 |
| `not_observed` | 他の通信は取得できたが、その操作後には対応通信がなかった |
| `capture_failed` | キャプチャ全体が機能していない可能性がある |

`tunnel_only`、`not_observed`、`capture_failed`は安全を意味せず、`Unknown`または`Unverified`として扱います。`capture_detail=https_connect_tunnel`は通信エラーではなく、CONNECT試行だけを観測したことを表します。

通信主体については、PCAPdroid等のpackage情報がある行だけ`traffic_owner`と`owner_confidence=high`を設定します。mitmproxy単独ではAndroid OS、Chrome、Google Play Services、対象アプリを区別できないため、`traffic_owner=unknown`として扱います。

### 5.2 統合Findingの状態

| 値 | 意味 |
| --- | --- |
| `Confirmed` | 動的解析だけで確認した挙動 |
| `Potential` | 静的候補はあるが、今回の操作では未確認 |
| `Supported` | 静的候補と動的観測が同じ通信先またはデータカテゴリで一致 |
| `Unverified` | キャプチャ障害、本文未取得、操作不足などで確認不能 |

`confidence`は根拠の確からしさ、`review_priority`は確認する順序です。High/Medium/Lowや上記状態は開発意図との一致を自動判定するものではありません。`review_question`を読み、開発者が仕様、使用SDK、想定通信先と比較してください。

### 5.3 開発者が確認する順番

1. `Unverified`を確認し、キャプチャ経路または操作シナリオに問題がないか判断する
2. `review_priority=high`のFindingを確認する
3. `Supported`を確認し、静的実装候補と実際の通信が意図どおりか判断する
4. `Confirmed`を確認し、動的にのみ現れた通信先が想定内か判断する
5. `Potential`を確認し、未使用コード・未実行経路・SDK由来のどれか判断する
6. `confidence=low`の項目は、断定せず追加調査候補として扱う

## 6. Streamlit画面

```bash
streamlit run app.py
```

サイドバーからAPKをアップロードして静的解析を実行でき、既存の静的解析JSON/CSVと`risk_results.csv`を表示できます。現在の画面は主に静的レポートと行ベース通信結果を表示するため、Evidence/Findingの詳細確認には`integrated_analysis.json`も併せて参照してください。

## 7. よくある問題

### APKのpackage名を取得できない

- `aapt`または`aapt2`へPATHを通す
- 一括実行時に`--package com.example.app`を指定する

### Manifest解析がpartialになる

- `static_analysis.json`の`stages`を確認する
- `aapt/aapt2`と`apkanalyzer`を確認する
- `ANDROID_HOME`または`ANDROID_SDK_ROOT`を確認する

### mitmproxyに通信が入らない

- `adb reverse --list`を確認する
- Androidのglobal proxyを確認する
- `mitmdump.log`を確認する
- 明示的なHTTP通信で端末からproxyへ到達できるか確認する
- PCAPdroidまたはWiresharkでパケットの存在を確認する
- Pinning、QUIC、独自通信の場合は`metadata_only`または`Unverified`として扱う
- proxy probeが`tool_unavailable`の場合は、Android shellに`curl`がないため自動確認できていません
- `Capture health: overall=partial`の場合は、CONNECTまたはエラーだけでHTTP詳細を取得できていない可能性があります

### すべて`capture_failed`になる

- `traffic_logs.csv`と`pcap_metadata.csv`がheaderだけになっていないか確認する
- キャプチャ開始後にアプリを操作したか確認する
- CSV時刻と端末時刻が大きくずれていないか確認する

### UI操作と通信が対応しない

- `--window`を実際の応答時間に合わせて変更する
- UIイベントと通信ログのepoch秒を確認する
- 起動直後やバックグラウンド通信は、特定のタップが原因とは断定しない

### 静的候補が多すぎる

- `source_file`と`source_type`を確認する
- Flutter、SDK、native library、アプリ独自コードを区別する
- `Potential`や`confidence=low`を実行確認済みの問題として扱わない

## 8. 研究実験で記録するもの

最低限、各実験について次を別途記録してください。

- APKのSHA-256、versionName、versionCode、package名
- 実験日時
- 端末またはEmulator名、Android API level
- アプリの初期状態、ログイン状態、権限付与状態
- 実行した操作シナリオ
- `--wait`、`--window`、`--max-events`
- mitmproxy、VPN/pcapの使用有無
- first-partyとして指定した`--allowed-domain`
- 静的解析・動的解析で使用した設定とバージョン
- 観測不能になった件数

同じAPKでも広告、A/Bテスト、キャッシュ、時刻、地域、アカウント状態により通信が変わります。評価では同じ条件を複数回実行し、何回中何回観測したかも記録してください。

## 9. テスト

通常のテスト:

```bash
python -m unittest discover -s tests -v
```

実APKを使った静的解析テスト:

```bash
TRAFFICISSUE_TEST_APK=/absolute/path/to/app.apk \
  python -m unittest tests.test_static_analyzer_real_apk -v
```

`pandas`がない環境では、動的ログ解析テストの一部がskipされます。評価・提出環境では`pandas`を導入し、実APK依存テスト以外がすべて実行される状態にしてください。
