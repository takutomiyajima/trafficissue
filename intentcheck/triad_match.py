"""Independent requirement, claim and explanation-coverage axes. No oracle inputs."""
from .adapter import adapt, normalize_url
from .validation import digest
from .sdk import REGISTRY

RULE_VERSION='triad-2.0'
LIMITS=['静的構成のみ。実行・取得・保存・送信・必要性・設計理由は未確認。',
        'SDK署名は固定した非難読化APIクラス集合。ベンダー真正性やSDK全体を保証しない。']


def match(case, report, sdk):
    facts=adapt(report)
    configurations=[]
    evidence=facts['evidence']
    def eid(kind, raw, pointer, member=None, locator=None):
        name=f'E-{len(evidence)+1:05d}'
        evidence.append({'evidence_id':name,'kind':kind,'raw_value':raw,'normalized_value':raw,
                         'source_report_pointer':pointer,'apk_member':member,'locator':locator,
                         'stage_id':'sdk','extraction_method':'dex_class_definitions' if kind=='sdk_signature' else 'string_hint',
                         'reliability':'signature_match' if kind=='sdk_signature' else 'string_hint'})
        return name
    for p in facts['permissions']:
        configurations.append({'domain':'permissions','key':p['permission'],'strength':'manifest_declaration' if p['verified'] else 'unverified','evidence_ids':p['evidence_ids']})
    for host in sorted({u['host'] for u in facts['url_candidates']}):
        configurations.append({'domain':'endpoints','key':host,'strength':'embedded_string',
                               'evidence_ids':[e for u in facts['url_candidates'] if u['host']==host for e in u['evidence_ids']]})
    for index,entry in enumerate(sdk['entries']):
        refs=[]
        for cls, locations in entry['classes'].items():
            for loc_index,loc in enumerate(locations):
                pointer='/triad_sdk/entries/'+str(index)+'/classes/'+cls.replace('~','~0').replace('/','~1')+'/'+str(loc_index)
                refs.append(eid(entry['strength'],cls,pointer,loc['apk_member'],loc['locator']))
        if not refs:
            refs.extend(eid('embedded_string',entry['sdk_id'],f'/triad_sdk/entries/{index}/hint_members/{i}',member) for i,member in enumerate(entry['hint_members']))
        configurations.append({'domain':'sdk','key':entry['sdk_id'],'strength':entry['strength'],'evidence_ids':refs})
    # Legacy SDK hints are candidates only, never silently upgraded to signatures.
    for label, metadata in facts['sdk_metadata'].items():
        sid=metadata.get('id')
        if sid in {r['sdk_id'] for r in REGISTRY['rules']} and facts['sdk_hints'].get(label) and not any(c['domain']=='sdk' and c['key']==sid for c in configurations):
            ref=eid('embedded_string',facts['sdk_hints'][label],'/sdk_hints/'+label.replace('~','~0').replace('/','~1'))
            configurations.append({'domain':'sdk','key':sid,'strength':'embedded_string','evidence_ids':[ref]})
    for c in configurations:
        c['configuration_id']='CFG-'+digest((c['domain']+':'+c['key']).encode())[:16]
    findings=[]
    def add(axis, verdict, domain, reqs=None, claims=None, configs=None, refs=None, reason='', rule=None):
        reqs,claims,configs,refs=reqs or [],claims or [],configs or [],refs or []
        fid='F-'+digest(str((axis,verdict,domain,reqs,claims,configs,len(findings))).encode())[:16]
        findings.append({'finding_id':fid,'axis':axis,'domain':domain,'verdict':verdict,
            'requirement_ids':reqs,'claim_ids':claims,'configuration_ids':configs,'evidence_ids':list(dict.fromkeys(refs)),
            'rule_id':rule or {'requirement':'R','claim':'C','coverage':'O'}[axis]+'-'+domain.upper()+'-01',
            'rule_version':RULE_VERSION,'reason':reason,'next_check':'原文と構成を確認し、採用または変更を判断してください。',
            'limitations':LIMITS})
    for domain in ('permissions','endpoints','sdk','behavior'):
        reqs=[r for r in case['requirements'] if r['domain']==domain]
        if not reqs:
            add('requirement','unspecified',domain,reason='明示的な制約なし。構成の不要・違反を意味しない。')
        for r in reqs:
            rid=[r['requirement_id']]
            if not r['explicit']:
                add('requirement','unspecified',domain,rid,reason='明示されていない制約は判定に使わない。'); continue
            if domain=='behavior':
                add('requirement','out_of_scope',domain,rid,reason='実挙動は静的構成の対象外。'); continue
            affected=[]
            for c in configurations:
                if c['domain']!=domain: continue
                if domain=='permissions': violation=c['key'] not in r['value']
                elif domain=='sdk': violation=c['key'] in r['value']
                else: violation=not any(c['key']==v['host'] or v['include_subdomains'] and c['key'].endswith('.'+v['host']) for v in r['value'])
                if violation:
                    affected.append(c)
                    strong=c['strength'] in ('manifest_declaration','sdk_signature')
                    add('requirement','mismatch' if strong else 'needs_review',domain,rid,
                        configs=[c['configuration_id']],refs=c['evidence_ids'],reason='明示制約の範囲外構成。URL・弱いヒントは違反確定としない。')
            complete=domain in ('permissions','endpoints') and facts['coverage'][domain]
            if not complete:
                add('requirement','unknown',domain,rid,reason='必要な走査範囲の証拠不足。SDK非検出は不存在を意味しない。')
            elif not affected:
                refs=[facts['coverage_evidence'][domain]]+[e for c in configurations if c['domain']==domain for e in c['evidence_ids']]
                add('requirement','conform_in_scope',domain,rid,refs=refs,reason='対応する静的構成の確認範囲内で制約を満たす。')
    explanation_docs=[d for d in case['documents'] if d['kind']=='explanation']
    if not explanation_docs:
        add('claim','explanation_unavailable','all',reason='説明原文未提供。説明漏れと扱わない。')
    for c in case['claims']:
        domain=c['domain']; cid=[c['claim_id']]; reqs=c['requirement_ids']
        if c['speech_act']!='implemented':
            add('claim','not_asserted',domain,reqs,cid,reason='提案・予定・例示は実装済み主張ではない。'); continue
        if domain=='behavior':
            add('claim','out_of_scope',domain,reqs,cid,reason='実際の取得・保存・送信は静的構成のみでは確認できない。'); continue
        if c['certainty']!='asserted' or c['scope']!='exact':
            add('claim','insufficient_evidence',domain,reqs,cid,reason='可能性・総称の説明を特定構成の断言へ変換しない。'); continue
        if domain=='permissions':
            found=[x for x in configurations if x['domain']==domain and x['key']==c['value']]
        elif domain=='endpoints':
            _,url=normalize_url(c['value'])
            found=[u for u in facts['url_candidates'] if u['url']==url]
        else: found=[x for x in configurations if x['domain']==domain and x['key']==c['value']]
        refs=[e for x in found for e in x['evidence_ids']]
        strong=bool(found) and (domain=='endpoints' or all(x['strength'] in ('manifest_declaration','sdk_signature') for x in found))
        complete=domain in ('permissions','endpoints') and facts['coverage'][domain]
        if strong:
            verdict='supported_in_scope' if c['predicate']=='present' else 'contradicted'
        elif not found and complete:
            verdict='contradicted' if c['predicate']=='present' else 'supported_in_scope'
            refs=[facts['coverage_evidence'][domain]]
        else: verdict='insufficient_evidence'
        add('claim',verdict,domain,reqs,cid,refs=refs,reason='原文の対象・肯否・条件と静的証拠を比較。SDK非検出だけでは否定を支持しない。')
    for config in configurations:
        domain=config['domain']
        def addresses(c):
            if c['domain']!=domain or c['scope']!='exact': return False
            if domain=='endpoints': return normalize_url(c['value'])[0]==config['key']
            return c['value']==config['key']
        mentions=[c for c in case['claims'] if addresses(c)]
        general=[c for c in case['claims'] if c['domain']==domain and c['scope']=='general']
        complete=bool(explanation_docs) and all(d['review']['status']=='complete' for d in explanation_docs)
        if mentions:
            verdict='covered' if any(c['speech_act']=='implemented' and c['certainty']=='asserted' for c in mentions) else 'partially_covered'
        elif general: verdict='ambiguous'
        elif complete: verdict='omission_candidate'
        else: verdict='not_evaluable'
        add('coverage',verdict,domain,claims=[c['claim_id'] for c in mentions+general],configs=[config['configuration_id']],refs=config['evidence_ids'],
            reason='記載の対応と説明の正誤は別軸。説明全文の確認完了時だけ説明漏れ候補を出す。構成強度: '+config['strength'])
    facts['sdk']=sdk
    return {'facts':facts,'configurations':configurations,'findings':findings,
            'stages':facts.pop('stages')+[dict(sdk['stage'],stage_id='sdk')],
            'summary':{axis:{v:sum(f['axis']==axis and f['verdict']==v for f in findings) for v in sorted({f['verdict'] for f in findings if f['axis']==axis})} for axis in ('requirement','claim','coverage')},
            'has_unknowns':any(f['verdict'] in ('unknown','insufficient_evidence','not_evaluable','explanation_unavailable') for f in findings) or not all(facts['coverage'][d] for d in ('permissions','endpoints')) or sdk['stage']['coverage']!='complete_in_scope'}
