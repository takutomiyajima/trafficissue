from collections import Counter
from .adapter import DOMAINS, adapt
from .http_policy import evaluate_http, SUPPORT_MATRIX
from .validation import digest, REGISTRY_VERSION
import json
from pathlib import Path

RULE_VERSION = '1.0'
REGISTRY = {'version': REGISTRY_VERSION, 'mode': 'string_hints_only',
            'ids': ['adjust', 'appsflyer', 'facebook', 'firebase_analytics', 'google_ads', 'google_maps'],
            'structural_signature_support': False}
REGISTRY_HASH = digest(json.dumps(REGISTRY, sort_keys=True).encode() + (Path(__file__).resolve().parent.parent/'config/sdk_signatures.yml').read_bytes())
LIMITATIONS = {
    'permissions': ['Manifestの宣言のみ。権限付与・API実行・機能上の必要性は未確認。既存JSONの名前一覧は所在情報に制約がある。'],
    'endpoints': ['実通信は未確認。抽出したHTTP(S) URL文字列候補に限定。生成URL・暗号化・動的ロード・未対応メンバーは範囲外。'],
    'cleartext_configuration': ['Androidプラットフォーム設定の解釈のみ。設定を参照しない通信実装や実際の送信は未確認。'],
    'sdk_inclusion': ['既存SDK検出は文字列ヒント。構造的署名・難読化対応が未検証のため、確定同梱や不存在は判定しない。']}
RULES = dict(zip(DOMAINS, ['PERM-01', 'URL-01', 'HTTP-01', 'SDK-01']))


def match_report(intent, report):
    facts = adapt(report)
    findings, summaries = [], {}
    def add(domain, verdict, fact, evidence_ids, reason):
        findings.append({'finding_id': f'F-{RULES[domain]}-{len(findings)+1:05d}',
                         'requirement_id': domain, 'rule_id': RULES[domain], 'rule_version': RULE_VERSION,
                         'domain': domain, 'verdict': verdict,
                         'intent_text': json.dumps(intent[domain], ensure_ascii=False, sort_keys=True),
                         'fact': fact, 'evidence_ids': evidence_ids, 'reason': reason,
                         'scope': {'permissions': 'Manifest宣言権限', 'endpoints': '抽出URL候補',
                                   'cleartext_configuration': '指定API・default構成のHTTP許可設定',
                                   'sdk_inclusion': '登録済みSDK文字列ヒント'}[domain],
                         'limitations': LIMITATIONS[domain]})
    for domain in DOMAINS:
        policy = intent[domain]
        start = len(findings)
        complete = facts['coverage'][domain]
        if policy['mode'] == 'unspecified':
            add(domain, 'unspecified', {}, [], '比較する方針が未指定。抽出事実は参考情報として保持。')
        elif domain == 'permissions':
            for p in facts['permissions']:
                if p['permission'] not in policy['allowed']:
                    add(domain, 'mismatch' if p['verified'] else 'candidate', {'permission': p['permission'], 'conditions': p['conditions']}, p['evidence_ids'], '宣言権限が許可集合に含まれない。')
            if not complete:
                add(domain, 'unknown', {}, [], '宣言権限の完全な走査を確認できない。フィールド欠落は0件とみなさない。')
            elif len(findings) == start:
                add(domain, 'conform_in_scope', {}, [], '走査したManifest宣言権限は許可集合内。')
        elif domain == 'endpoints':
            for u in facts['url_candidates']:
                allowed = any(u['host'] == a['host'] or (a['include_subdomains'] and u['host'].endswith('.'+a['host'])) for a in policy['allowed_hosts'])
                if not allowed:
                    add(domain, 'candidate', {'url': u['url'], 'host': u['host']}, u['evidence_ids'], '抽出URL候補のホストが許可範囲外。実通信は未確認。')
            if not complete:
                add(domain, 'unknown', {}, [], 'URL候補の対応範囲の走査完了を確認できない。')
            elif len(findings) == start:
                add(domain, 'conform_in_scope', {}, [], '抽出したURL候補内では範囲外候補なし。実通信は未確認。')
        elif domain == 'cleartext_configuration':
            results = []
            config = facts['http_configuration']
            for api in policy['runtime_api_levels']:
                result = evaluate_http(config, api, policy['resource_profile'])
                results.append(result)
                eid = []
                if result['verdict'] != 'unknown':
                    name = f'E-{len(facts["evidence"])+1:05d}'
                    facts['evidence'].append({'evidence_id': name, 'kind': 'http_configuration',
                        'raw_value': config, 'normalized_value': result, 'extraction_method': 'manifest_nsc_interpretation',
                        'source_report_pointer': '/intentcheck_extraction/http_configuration', 'apk_member': 'AndroidManifest.xml',
                        'locator': '/manifest/application', 'stage_id': domain, 'reliability': 'verified_structure'})
                    eid = [name]
                add(domain, result['verdict'], result, eid,
                    result.get('reason', '実効設定に許可範囲が存在。' if result['verdict']=='mismatch' else '対応範囲の実効設定はすべて平文通信禁止。'))
            facts['http_effective'] = results
            facts['http_support_matrix'] = SUPPORT_MATRIX
            complete = all(r['verdict'] != 'unknown' for r in results)
            facts['coverage'][domain] = complete
        elif domain == 'sdk_inclusion':
            complete = not policy['denied_sdk_ids']
            facts['coverage'][domain] = complete
            if complete:
                add(domain, 'conform_in_scope', {}, [], '個別禁止SDKの指定なし。SDK走査完了を意味しない。')
            else:
                metadata = facts['sdk_metadata']
                hints = facts['sdk_hints']
                if isinstance(metadata, dict) and isinstance(hints, dict):
                    for label, meta in metadata.items():
                        if isinstance(meta, dict) and meta.get('id') in policy['denied_sdk_ids'] and hints.get(label):
                            eid = f'E-{len(facts["evidence"])+1:05d}'
                            facts['evidence'].append({'evidence_id': eid, 'kind': 'sdk_hint', 'raw_value': hints[label],
                                'normalized_value': meta['id'], 'extraction_method': 'legacy_string_hint',
                                'source_report_pointer': '/sdk_hints/'+label.replace('~','~0').replace('/','~1'),
                                'apk_member': None, 'locator': None, 'stage_id': domain, 'reliability': 'string_hint'})
                            add(domain, 'candidate', {'sdk_id': meta['id']}, [eid], '禁止SDKの文字列ヒント。構造的署名は未検証。')
                add(domain, 'unknown', {}, [], '非空の禁止SDK一覧に対し、検証済み識別器・走査範囲の証拠が不足。')
        current = findings[start:]
        counts = Counter(f['verdict'] for f in current)
        verdict = next((v for v in ('unspecified','mismatch','candidate') if counts[v]), 'conform_in_scope' if complete and not counts['unknown'] else 'unknown')
        summaries[domain] = {'verdict': verdict, 'counts': dict(counts),
                             'has_unknowns': policy['mode'] != 'unspecified' and not complete,
                             'scope': current[0]['scope'], 'limitations': LIMITATIONS[domain]}
    facts['counts'] = {'permission_names': len(facts['permissions']), 'url_candidates': len(facts['url_candidates']),
                       'url_occurrences': sum(len(u['evidence_ids']) for u in facts['url_candidates']),
                       'url_hosts': len({u['host'] for u in facts['url_candidates']})}
    return facts, findings, summaries
