"""Compare semantic facts; incomplete extraction never proves removal/resolution."""
from .adapter import DOMAINS
from .validation import CheckError, digest
import json


def key(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def compare(before, after, episode_id):
    for field in ('result_schema_version',):
        if before.get(field) != '1.0' or after.get(field) != '1.0':
            raise CheckError('INCOMPARABLE_RUNS', 'unsupported result schema')
    checks = [(before['intent']['id'], after['intent']['id']),
              (before['intent']['version'], after['intent']['version']),
              (before['intent']['sha256'], after['intent']['sha256']),
              (before['application'].get('package_name'), after['application'].get('package_name'))]
    for f in ('adapter', 'rule_version', 'registry_hash', 'extractor_version', 'http_support_matrix'):
        checks.append((before['provenance'].get(f), after['provenance'].get(f)))
    if any(a != b for a,b in checks) or not before['application'].get('package_name'):
        raise CheckError('INCOMPARABLE_RUNS', 'intent, package, adapter, extractor, HTTP support matrix or rules differ; explicit cross-package episodes are not supported')
    differences = []
    def facts(run, domain):
        f = run['facts']
        if domain == 'permissions':
            return {p['permission'] for p in f['permissions']}
        if domain == 'endpoints':
            return {u['url'] for u in f['url_candidates']}
        if domain == 'cleartext_configuration':
            return {key({'runtime_api': x['runtime_api'], 'range': r}) for x in f.get('http_effective', []) for r in x['ranges']}
        return {f['fact']['sdk_id'] for f in run['findings'] if f['domain']==domain and 'sdk_id' in f['fact']}
    for domain in DOMAINS:
        left, right = facts(before, domain), facts(after, domain)
        lc, rc = before['facts']['coverage'][domain], after['facts']['coverage'][domain]
        for value in sorted(left | right):
            change = 'unchanged' if value in left & right else ('added' if value in right and lc else 'removed' if value in left and rc else 'unknown')
            differences.append({'domain': domain, 'fact_key': value, 'change': change})
    relations = []
    def finding_index(run):
        result = {}
        for f in run['findings']:
            if f['verdict'] not in ('mismatch', 'candidate'):
                continue
            fact = f['fact']
            # Conditions/locations are evidence, not identity.
            if f['domain'] == 'permissions':
                fact = {'permission': fact['permission']}
            elif f['domain'] == 'endpoints':
                fact = {'url': fact['url']}
            elif f['domain'] == 'cleartext_configuration':
                fact = {'runtime_api': fact['runtime_api']}
            result[(f['domain'], key(fact))] = f
        return result
    a, b = finding_index(before), finding_index(after)
    for index in sorted(a.keys() | b.keys()):
        domain, fact = index
        old, new = a.get(index), b.get(index)
        unknown_before = before['summaries'][domain]['has_unknowns']
        unknown_after = after['summaries'][domain]['has_unknowns']
        if old and new and old['verdict'] == new['verdict']:
            relation = 'persistent_mismatch' if new['verdict']=='mismatch' else 'unchanged'
        elif old and not new and not unknown_after:
            relation = 'resolved_'+old['verdict']
        elif new and not old and not unknown_before:
            relation = 'new_'+new['verdict']
        else:
            relation = 'comparison_unknown'
        relations.append({'domain': domain, 'fact_key': fact, 'relation': relation,
                          'before_finding': old['finding_id'] if old else None,
                          'after_finding': new['finding_id'] if new else None,
                          'reason': '発生時点・解消を確定できない。解析不能を削除としない。' if relation=='comparison_unknown' else '同一意図・ルールによる抽出事実の比較。実通信の開始・停止や変更原因は未確認。'})
    partial = any(s['has_unknowns'] for r in (before,after) for s in r['summaries'].values())
    return {'comparison_schema_version': '1.0', 'episode_id': episode_id,
            'before_run_id': before['run_id'], 'after_run_id': after['run_id'],
            'before_result_sha256': digest(key(before).encode()), 'after_result_sha256': digest(key(after).encode()),
            'facts': differences, 'relations': relations, 'partial': partial}
