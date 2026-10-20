import re
from urllib.parse import urlsplit, urlunsplit
from .validation import CheckError, host

ADAPTER_VERSION = 'trafficissue-static-1.0'
DOMAINS = ('permissions', 'endpoints', 'cleartext_configuration', 'sdk_inclusion')


def normalize_url(raw):
    if not isinstance(raw, str) or re.search(r'[\s\x00-\x1f]', raw):
        raise ValueError('invalid URL string')
    p = urlsplit(raw)
    if p.scheme.lower() not in ('http', 'https') or not p.hostname:
        raise ValueError('absolute HTTP(S) URL required')
    name = host(p.hostname)
    port = p.port if p.port is not None else (443 if p.scheme.lower() == 'https' else 80)
    netloc = f'[{name}]' if ':' in name else name
    # Userinfo stays in raw evidence; candidate identity is scheme/host/port/path/query.
    key = urlunsplit((p.scheme.lower(), netloc+':'+str(port), p.path or '/', p.query, ''))
    return name, key


def adapt(report):
    if not isinstance(report, dict):
        raise CheckError('UNSUPPORTED_SCHEMA', 'static report must be an object')
    version = report.get('schema_version')
    # The checked-in historical report predates schema_version; recognize only its signature.
    legacy = version is None and all(k in report for k in ('application', 'analysis_status', 'stages', 'findings'))
    if version != '1.0' and not legacy:
        raise CheckError('UNSUPPORTED_SCHEMA', 'expected trafficissue static schema 1.0')
    if not isinstance(report.get('application'), dict) or not isinstance(report.get('stages'), dict):
        raise CheckError('UNSUPPORTED_SCHEMA', 'application and stages objects required')
    for k in ('permissions', 'findings'):
        if k in report and (not isinstance(report[k], list) or any(not isinstance(x, dict) for x in report[k])):
            raise CheckError('UNSUPPORTED_SCHEMA', k+' must be an object array')
    evidence, permissions, urls, references, excluded = [], {}, {}, [], []
    warnings = []
    def add(kind, raw, normalized, pointer, stage, reliability, member=None, locator=None, method='legacy_report'):
        eid = f'E-{len(evidence)+1:05d}'
        evidence.append(dict(evidence_id=eid, kind=kind, raw_value=raw, normalized_value=normalized,
                             extraction_method=method, source_report_pointer=pointer, apk_member=member,
                             locator=locator, stage_id=stage, reliability=reliability))
        return eid
    stages = []
    for key, stage in report['stages'].items():
        if not isinstance(stage, dict):
            raise CheckError('UNSUPPORTED_SCHEMA', 'stage must be an object')
        # Legacy stage success has no coverage guarantee. Only our extractor contract can attest scope.
        stages.append(dict(stage, stage_id=key, coverage='unknown'))
    extension = report.get('intentcheck_extraction')
    if extension is not None and (not isinstance(extension, dict) or extension.get('version') != '1.0'):
        raise CheckError('UNSUPPORTED_SCHEMA', 'unsupported intentcheck extraction extension')
    ext = extension or {}
    coverage = {d: False for d in DOMAINS}
    for d in ('permissions', 'endpoints'):
        s = ext.get('stages', {}).get(d, {})
        coverage[d] = s.get('status') == 'success' and s.get('coverage') == 'complete_in_scope'
        if s:
            stages.append(dict(s, stage_id=d))
    if 'permissions' not in report:
        coverage['permissions'] = False
    else:
        for i, p in enumerate(report['permissions']):
            name = p.get('name')
            if not isinstance(name, str) or not name:
                coverage['permissions'] = False
                warnings.append({'code': 'MISSING_EVIDENCE', 'path': f'/permissions/{i}'})
                continue
            s = report['stages'].get('manifest_badging_analysis', report['stages'].get('manifest_analysis', {}))
            reliable = s.get('status') == 'success' or bool(ext.get('permissions_structural'))
            eid = add('permission', name, name, f'/permissions/{i}', 'permissions',
                      'verified_structure' if reliable else 'unverified', 'AndroidManifest.xml', p.get('locator'))
            entry = permissions.setdefault(name, {'permission': name, 'evidence_ids': [], 'verified': reliable, 'conditions': []})
            entry['evidence_ids'].append(eid)
            entry['conditions'].append({k: v for k, v in p.items() if k not in ('name', 'locator')})
    source_urls = ext.get('url_occurrences')
    if source_urls is None:
        source_urls = []
        for i, f in enumerate(report.get('findings', [])):
            if f.get('signal_type') == 'url':
                member = re.search(r'source_file=(\S+)', str(f.get('evidence', '')))
                source_urls.append({'value': f.get('value'), 'pointer': f'/findings/{i}',
                                    'apk_member': member.group(1) if member else None})
            elif f.get('signal_type') == 'domain':
                references.append({'value': f.get('value'), 'source_report_pointer': f'/findings/{i}', 'role': 'reference_only'})
    if not isinstance(source_urls, list) or any(not isinstance(x, dict) for x in source_urls):
        raise CheckError('UNSUPPORTED_SCHEMA', 'URL occurrences must be an object array')
    for i, item in enumerate(source_urls):
        raw = item.get('value')
        pointer = item.get('pointer', f'/intentcheck_extraction/url_occurrences/{i}')
        try:
            name, key = normalize_url(raw)
        except (ValueError, UnicodeError):
            references.append({'value': raw, 'source_report_pointer': pointer, 'role': 'unparsed_url'})
            coverage['endpoints'] = False
            continue
        eid = add('url', raw, key, pointer, 'endpoints', 'string_hint', item.get('apk_member'), item.get('locator'), item.get('method', 'member_string'))
        if item.get('role') == 'xml_namespace' and item.get('method') == 'xml_namespace_declaration':
            excluded.append({'evidence_id': eid, 'reason': 'Structurally verified XML namespace occurrence'})
            continue
        u = urls.setdefault(key, {'url': key, 'host': name, 'evidence_ids': []})
        u['evidence_ids'].append(eid)
    if 'findings' not in report and 'url_occurrences' not in ext:
        coverage['endpoints'] = False
    return {'evidence': evidence, 'permissions': sorted(permissions.values(), key=lambda x: x['permission']),
            'url_candidates': sorted(urls.values(), key=lambda x: x['url']), 'reference_only': references,
            'excluded_occurrences': excluded, 'http_configuration': ext.get('http_configuration', {}),
            'sdk_hints': report.get('sdk_hints', {}), 'sdk_metadata': report.get('sdk_metadata', {}),
            'coverage': coverage, 'stages': stages, 'warnings': warnings}
