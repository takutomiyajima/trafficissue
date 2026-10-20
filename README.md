# trafficissue

UI操作ログと通信観測ログを時刻で対応付け、Androidアプリの「どの操作の後に、どの通信先が、どの程度観測できたか」を整理するためのMVPです。

セットアップ、一括解析、個別実行、出力の読み方、トラブルシューティングを含む詳細な手順は、[`docs/usage_guide.md`](docs/usage_guide.md)を参照してください。

## 開発意図とAPKの照合（intentcheck）

APKの解析結果から、開発者が**独立して記録した構造化方針**への抵触を調べるCLIを追加しました。
既存の通信観測・静的解析とは別の入口です。解析で見つかったドメインを許可リストへ自動転記せず、
元要求の自由文も自動解釈しません。実通信、情報漏えい、アプリ全体の安全性は判定しません。

### 使い方

Python 3.10以降と既存の依存関係を使用します。JSON取込・照合自体には追加の外部パッケージは不要です。
APK解析は既存の`static_analyzer.py`を再利用し、Manifest／NSCのバイナリXMLには`apkanalyzer`を使用します。
クラウド環境では`source /workspace/trafficissue-tools/activate.sh`で導入済みの環境を有効化できます。

まず[意図ファイルの例](examples/intentcheck/intent.json)をコピーし、実際の要求に合わせてID・版・記録時刻・方針を編集してください。
この例は説明用の架空方針であり、既存APKの生成前要求を再現したものではありません。

```bash
# 構文・型・未知キー・矛盾・登録SDK IDなどを検証
python -m intentcheck validate-intent --intent examples/intentcheck/intent.json

# 既存の静的JSONを読み込む。過去のレポートや意図を上書きしない新規出力先を指定
python -m intentcheck match --intent examples/intentcheck/intent.json \
  --static-report logs/static_analysis.json --case-id C001 --out /tmp/intentcheck-C001

# APK自体は実行せず、静的解析から照合まで行う
python -m intentcheck analyze --intent examples/intentcheck/intent.json \
  --apk /absolute/path/app.apk --case-id C002 --out /tmp/intentcheck-C002

# 同じ意図ファイル・ルール・解析方式で作成した修正前後の結果を比較
python -m intentcheck compare --before /tmp/intentcheck-before/result.json \
  --after /tmp/intentcheck-after/result.json --episode-id EP001 --out /tmp/intentcheck-EP001

# 既存機能を含むテスト。実APKテストのみ環境変数未設定時にskip
python -m unittest discover -s tests -v
```

`match`に`--apk`も指定した場合は実体のSHA-256とレポート記録を照合し、欠落・不一致を拒否します。
JSONだけなら`identity_verification=report_only`であり、APK実体を検証したことにはしません。
意図JSONは4領域を必須とし、指定しない領域は`{"mode":"unspecified"}`と明記します。
空の権限／ホスト許可リストは「許可なし」であり、未指定とは異なります。
未知キー、null、重複JSONキー、型違いは拒否します。同一配列値の重複は警告付きで統合します
（実行APIの重複は仕様に従いエラー）。ホストはDNS名・IPのみで、スキーム・ポート・パス・ワイルドカードは入力できません。

### 照合の仕組み

`入力検証 → 既存解析／JSON取込 → 証拠と走査範囲の正規化 → 方針照合 → レポート → 任意の前後比較`
の順で処理します。実装は`intentcheck/`に分離し、既存の解析CLIや画面の使い方を保持しています。

| 項目 | 比較する内容 | 結果と制約 |
|---|---|---|
| PERM-01 | Manifestの宣言権限と完全な権限名の許可集合 | 範囲外の信頼できる宣言は`mismatch`。権限付与・API実行は未確認 |
| URL-01 | HTTP(S)絶対URLからパーサーで取得したホストと許可ホスト | 範囲外は`candidate`。userinfoを区別し、サブドメインはドット境界で比較。DNS解決・URL接続はしない |
| HTTP-01 | ManifestとNSCの実効平文通信許可設定 | 対応環境で許可範囲があれば`mismatch`。NSC優先・base-config／domain-configの継承を解釈 |
| SDK-01 | 登録済みSDKの既存文字列ヒント | ヒントがあれば`candidate`。検証済み構造署名がないため非空denylistの完全な適合は出さない |

判定は`mismatch`（不一致確認）、`candidate`（候補）、`conform_in_scope`（確認範囲で適合）、
`unknown`（確認不能）、`unspecified`（未指定）の5種類です。領域別要約に`has_unknowns`を併記し、
一部に不一致が見つかっても未確認範囲を隠しません。総合安全スコアは出しません。

既存JSONの`analysis_status=success`だけでは完全性を保証できないため、従来レポートを取り込む場合は
走査範囲を`unknown`とします。見つかった証拠は報告しますが、欠落フィールドを空集合や適合に変換しません。
`schema_version=1.0`およびリポジトリ同梱の旧レポートの特徴を持つ形式を認識し、それ以外は拒否します。
`analyze`で追加する`intentcheck_extraction.version=1.0`が、宣言権限とURL走査の範囲を記録します。
同じURLの複数出現は証拠IDを残して候補へ統合し、handoff由来の重複は加算しません。
候補数・出現数・ホスト数を分離し、構造確認できたXML名前空間の出現だけを対象外にします。

HTTPの対応表は`intentcheck/http_policy.py`の`SUPPORT_MATRIX`にあります。
通常インストールされたアプリ、runtime API 23〜35、target SDK 1〜35、defaultリソース構成を対象とします。
API 24以降でNSC参照がある場合はNSCを優先し、API 23ではManifestを使います。
NSCの未指定属性は親設定・対応環境の既定値を継承します。リソース修飾子付きNSC、未解決参照、
未対応API・構成・属性は`unknown`です。API別の実機検証が完了したという意味ではありません。
公式Developer文書へのアクセスは本クラウド環境では403だったため、既定値と継承は固定版の
[AOSP NetworkSecurityConfig](https://github.com/aosp-mirror/platform_frameworks_base/blob/android-15.0.0_r1/core/java/android/security/net/config/NetworkSecurityConfig.java)と
[XmlConfigSource](https://github.com/aosp-mirror/platform_frameworks_base/blob/android-15.0.0_r1/core/java/android/security/net/config/XmlConfigSource.java)も確認しています。

SDK台帳版は`trafficissue-hints-1`、IDは`firebase_analytics`, `google_ads`, `google_maps`, `facebook`, `adjust`, `appsflyer`です。
禁止IDの未登録・台帳版違いは入力エラーです。空の禁止リストは「個別禁止SDKの指定なし」であり、
SDKを走査して不存在を確認したことにはしません。M3の検証済み構造署名による確定同梱判定は未実装です。

### 出力と比較・人手レビュー

新規の出力ディレクトリに以下を保存します。既存ディレクトリへの出力は拒否します。

| ファイル | 内容 |
|---|---|
| `result.json` | 方針スナップショット・ハッシュ、対象APK、領域別要約、証拠IDと判定の正式な結果 |
| `report.md` | 要求・抽出事実・理由・所在・限界を組にした日本語レポート |
| `findings.csv` | 1行1判定。複数値はJSON、表計算用の数式開始記号は無害化 |
| `run.json` | 入力ハッシュ、ルール版、アダプター版、環境、引数、時間、メモリ計測、資源上限 |
| `source_static_analysis.json` | 受領または生成した元解析JSONのコピー |
| `case.json` | run_id・case_id・APK・意図版を結ぶケース台帳レコード |

証拠には元JSON Pointer、APKメンバー、取得方法、信頼度を残します。不明なクラス・行番号は生成しません。
前後比較では`comparison.json`と`comparison.md`を生成し、証拠の追加・削除と方針上の変化を分離します。
同一意図のID・版・ファイルハッシュ、ルール・アダプター・解析方式・SDK台帳が異なる比較や、
異なるパッケージの比較は拒否します。前が確認不能なら後の不一致を`new_mismatch`とせず
`comparison_unknown`にし、後の抽出失敗を削除・解消と扱いません。URL候補の削除は通信停止を意味しません。

人手レビューは次の形式の配列を別ファイルに保存し、`join-reviews`で対応付けます。
自動判定の書き換えや自動照合への正解入力は行いません。

```json
[{"run_id":"result.jsonのrun_id", "finding_id":"対応するfinding_id", "reviewer":"確認者", "note":"確認した根拠"}]
```

```bash
python -m intentcheck join-reviews --result /tmp/intentcheck-C001/result.json \
  --reviews /absolute/path/manual-reviews.json --out /tmp/intentcheck-review-C001
```

終了コードは`0`＝処理・出力完了（不一致があっても正常）、`2`＝入力不正、
`3`＝証拠不足・部分成功・未対応（可能なレポートは保存）、`4`＝ツール・I/O等の実行失敗です。
失敗途中の出力には`INCOMPLETE`を付けます。実行失敗時には適合結果を生成しません。

### 対応範囲と残る検証

資源上限は`match`／`analyze`の`--config`で変更できます（例：`{"resource_limits":{"tool_timeout_seconds":120}}`）。
未知キー・0以下・整数以外は拒否します。既定値はAPK上限300 MiB、JSON上限100 MiB、展開総量2 GiB、10万メンバー、追加走査の1メンバー64 MiB、
外部解析の制限時間300秒・アドレス空間4 GiBとし、実値を`run.json`に記録します。
APKは実行・外部送信せず、危険なアーカイブパス・重複メンバーを拒否し、作業場所を実行ごとに分離します。
抽出はLinuxで検証しています。APKのURL追加走査はDEX・XML・テキスト・assets内のASCII文字列が対象で、
ネイティブバイナリ（Flutterを含む）、UTF-16、生成・暗号化URLは対象外です。
既存解析器の資源超過・タイムアウトで継続できない場合は終了コード4で止め、適合を報告しません。

開発用ケースで入力検証、ホスト偽装・サブドメイン境界、HTTP継承、部分失敗、前後比較、
レポート間の判定一致を検証しています。同梱の実レポート1件でも取込を検証しています。
研究評価用の独立した正解付きAPK群、P03/P04両方の実データ、Android各APIでの実機検証、
難読化SDK署名の検証、別パッケージを結ぶエピソード台帳、
TP/FP/FN/TNの研究集計は今回の実装・検証範囲には含まれません。

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

HTTPS CONNECT先だけを取得した場合は`error`ではなく`tunnel_only`として扱います。また、mitmproxy単独では通信元packageを特定できないため`traffic_owner=unknown`とし、PCAPdroid等のpackage/UID情報がある場合だけ強い帰属根拠として使用します。

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

## 通信確認用デバッグ版の作成

Androidアプリのソースを別途用意できる場合は、`prepare_debug_proxy.py`でmitmproxy CAを信頼する設定を
`src/debug`だけへ生成できます。P00〜P04の評価APKを変更する機能ではなく、補助実験専用です。

```bash
python prepare_debug_proxy.py path/to/project/app ~/.mitmproxy/mitmproxy-ca-cert.pem
```

既存のdebug設定は既定で上書きしません。生成内容、ビルド時の確認事項、削除方法は
[`docs/usage_guide.md`](docs/usage_guide.md)を参照してください。

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

JSONには、動的解析が読み込みやすいバージョン付きの `dynamic_analysis_handoff` を出力します。ここには対象パッケージ、APKのSHA-256、静的に見つかった通信先・URL、センシティブデータカテゴリ、SDK IDを正規化して格納します。`analyze_logs.py --static-report` で読み込むと、まずUIのlaunchイベント（または明示した`--target-package`）と静的解析のpackage nameが一致することを検証します。不一致または動的ログの対象を特定できない場合は処理を停止し、異なるアプリの根拠を統合しません。一致した場合だけ、動的に観測した各通信へ `static_match`、`static_evidence`、`static_app_data_categories` が追加されます。最後の列はアプリ全体の静的候補であり、その通信先へ実際に送信したデータを意味しません。`run_analysis.py` ではこの連携を自動的に行います。

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
