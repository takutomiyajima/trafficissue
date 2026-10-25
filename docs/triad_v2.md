# v2 三者照合の設計・実装範囲

要件の原本は [要件定義 v2.0](requirements/static_analysis_requirements_v2.md)。従来の`match`・`analyze`・`compare`はv1の意味を保持し、新入口`triangulate`を追加する。旧判定から説明矛盾への暗黙変換はしない。

## 棚卸し（M0）

|既存情報|再利用先|限界|
|---|---|---|
|`application.sha256`|Artifact対応|JSONのみでは実体未検証|
|`permissions`・Manifest段階|権限構成・宣言主張|欠落を0件にしない。走査範囲不明なら負の主張を支持しない|
|`findings.signal_type=url`|URL候補・ホスト構成|実通信とはしない|
|`sdk_hints/sdk_metadata`|SDK候補|署名へ昇格しない|
|`intentcheck_extraction`|走査範囲とHTTP等|v2の必須照合ではHTTPを実行しない|
|`output_transaction`・`join-reviews`|出力保護・別管理の人手レビュー|原結果を書き換えない|

旅行記録アプリのAI回答・APK・独立正解表は、利用者の回答により未保存と確認した。その一式を必要とするM1完了判定と実データ評価は保留。開発用ケースは明示的な人工例であり、旅行記録アプリを実際に解析した結果ではない。

## 入力契約 `schema_version=2.0`

完全な例は [case.json](../examples/triad/case.json)。パスはcase.jsonの親から解決する。構造化入力の未知キー・不正型・未知列挙値・参照切れは終了コード2。JSON重複キーも拒否する。

- Case: `case_id`, `experiment_split`（development/evaluation/pilot）, `generation.series_id/conditions`。
- Artifact: `artifact_id`, `apk_sha256`（不明はnull）。文書のartifact_idを同じ成果物へ拘束し、説明の別APKへの流用を防ぐ。JSONに実体対応がなければunverified。評価用対応表の`evaluation_eligible`はAPK実体とcaseのハッシュ検証を必要とする。これは正解や解析の完全性を保証するフラグではない。
- Document: `document_id`, `kind`（request/explanation）, `path`, `sha256`, `version`, `artifact_id`, `origin_type`, `responded_at`, `review`。要求原文必須、説明なしは許容。origin_typeはinitial_response/posthoc_explanation/revision_response。応答日時不明はnull＋警告。全文確認状態はcomplete/partial/unknown。
- 人手の構造化確認: `confirmation.reviewer/reviewed_at`必須。元文書の`source.document_id/start_line/end_line`は1始まり・終端包含の行範囲。
- Requirement: `requirement_id`, `source`, `domain`, `predicate`, `value`, `scope`, `confirmation`, `explicit`。
- Claim: `claim_id`, `source`, `domain`, `predicate`, `value`, `scope`, `confirmation`, `speech_act`, `certainty`, `requirement_ids`。複数要求に対応できる。
- Domain: permissions/endpoints/sdk/behavior。Scope: exact/general。Speech: implemented/proposal/planned/example。Certainty: asserted/possible/uncertain。可能性表現を断言へ読み替えない。
- 追加のevidence_idを入力側から指定して自動判定を誘導することはできない。未知キーとして拒否する。原文自体から自由文の意味を抽出・検証する機能は持たず、人による構造化確認を前提にする。

|領域|要求predicate/value|説明predicate/value|
|---|---|---|
|permissions|allowlist / 完全権限名配列|present, absent / 完全権限名|
|endpoints|allowlist / `{host, include_subdomains}`配列|present, absent / HTTP(S) URL文字列|
|sdk|denylist / 台帳sdk_id配列|present, absent / sdk_id|
|behavior|runtime / 原文を保持する文字列|runtime / 原文を保持する文字列（対象外）|

要求なしはunspecified。allowlist=[]は明示的な許可なし。explicit=falseは判定制約に使わない。自由文の「通信しない」をINTERNET禁止へ変換しない。一般的な業務要件から権限の必要性を推論しない。

`redacted_path`は任意。原本とは別コピー・別ハッシュとして保管する。レポートは元文書の場所・構造化値を表示する。構造化値にも秘密情報が含まれる場合があるため、出力を自動的に共有可能な伏字済みと扱わない。

## 規則と三つの軸

`triad_match.py`に固定版`triad-2.0`を記録する。要求・説明・説明対応を独立したFindingとして出す。各findingは元要求ID・主張ID・構成ID・証拠ID・規則ID・理由・確認事項・限界を持つ。

- 要求: mismatch/conform_in_scope/needs_review/unspecified/unknown/out_of_scope。URL範囲外はneeds_review。
- 説明: supported_in_scope/contradicted/insufficient_evidence/out_of_scope/not_asserted/explanation_unavailable。権限の存在主張は完全走査で不在ならcontradicted。SDK非検出は常に不存在の証明にしない。
- 説明対応: covered/partially_covered/omission_candidate/ambiguous/not_evaluable。粒度は権限完全名・URL正規化ホスト・sdk_id。否定説明も言及あり。総称はambiguous。説明未提供・部分確認ならnot_evaluable。説明漏れ候補は全文確認complete時のみ。弱いSDK構成には証拠強度を併記する。

v2の規則は構造化した集合制約のみ。互いに反対の存在必須・禁止要求を同時に入力する形式は初版の対象外としてpredicate検証で拒否する。構造化前の自然言語同士の矛盾を自動検出することはできない。

## 固定SDK台帳

`intentcheck/sdk.py`の`dex-api-subsets-1`が対象を定める。

|sdk_id|署名（両クラスのDEX class_defが必須）|分類|
|---|---|---|
|google_maps|MapView, MapsInitializer（com.google.android.gms.maps）|location|
|firebase_analytics|FirebaseAnalytics, FirebaseAnalytics$Event（com.google.firebase.analytics）|analytics|

DEX 035〜040のサイズ・エンディアン・SHA-1署名・Adler32と参照境界を検証し、class_defs → type_ids → string_idsを解決する。文字列プールの単独出現とクラス定義を区別し、複数DEX（classes10.dex等を含む）を統合する。署名は**非難読化API部分集合の名前付きクラス定義の存在**に限る。ベンダー真正性・SDK全体・R8や動的ロードへの対応・実行・送信は保証しない。クラス名の偽装やコピーも除外できない。

人工の肯定・否定・単独文字列・破損・複数DEXケースで構造条件を検証する。実SDK依存のある実APKによる検出性能評価は未実施であり、FR-07の実環境検証まで完成したとは扱わない。旧台帳の他SDKはv1で候補表示可能だが、v2構造署名の対象へ黙って含めない。

## 出力・受入確認

`result.json`, `report.md`, `baseline.md`, `run.json`, `findings.csv`, `case.json`, `evaluation_units.json`, `raw_inputs/`を新規ディレクトリへ保存する。baselineとreportは同じ原文参照・全証拠・全findingを使い、順序だけを変える。どちらも情報量を増減させない。理解向上を実証した出力ではない。

`evaluation_units.json`は要求数・主張数・構成数・判定数を分離し、正解表との手動対応・後続評価に用いる。通常照合はoracleファイルを読み込まず、TP/FP等の正解依存集計は自動結果へ混入しない。独立正解表の作成と指標集計は実評価時の別工程とする。

|受入条件|開発用の確認|
|---|---|
|AC-01〜06|制約未指定・禁止宣言・説明否定・完全走査不在・欠落・部分失敗|
|AC-07,08,19〜21|URL候補の境界・userinfo・重複所在・因果経路を生成しない|
|AC-09〜15|SDK構造署名／ヒント／非検出・説明なし／部分確認／否定言及／提案|
|AC-16〜18|挙動対象外・APKハッシュ不一致・predicate／原文／ID参照検証|
|AC-22〜26|レビュー別管理・出力ID一致・結果再現・表示の同一情報・oracle非依存|

対応するテストは`tests/test_triad.py`。既存v1テストも実行する。合成ZIP＋XML＋DEXの試験を実APKやAndroidツールによる復号の試験と呼ばない。GUI・LLM・実アプリ修正・HTTP全環境解釈・v2修正前後比較はP2のため追加しない。生成時回答・実APK・独立正解表が揃うまでは、M1／M2の研究評価完了を宣言しない。
