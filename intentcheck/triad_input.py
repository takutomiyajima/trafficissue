"""Versioned human-confirmed structure, with original-file and artifact binding."""
from pathlib import Path
import datetime
import re
from .validation import CheckError, file_hash, host
from .sdk import REGISTRY


def error(path, message, code='INVALID_INPUT'):
    raise CheckError(code, path+': '+message)


def obj(value, required, optional, path):
    if not isinstance(value, dict) or set(required)-set(value) or set(value)-set(required)-set(optional):
        error(path, 'object has missing or unknown keys')


def text(value, path):
    if not isinstance(value, str) or not value.strip():
        error(path, 'nonempty string required')


def timestamp(value, path):
    try:
        if datetime.datetime.fromisoformat(value).utcoffset() is None:
            raise ValueError()
    except (ValueError, TypeError):
        error(path, 'timezone-aware ISO timestamp required')


def validate_case(case, base):
    obj(case, ['schema_version','case_id','experiment_split','generation','artifact','documents','requirements','claims'], [], '/')
    if case['schema_version'] != '2.0':
        error('/schema_version','only 2.0 is supported')
    text(case['case_id'],'/case_id')
    if case['experiment_split'] not in ('development','evaluation','pilot'):
        error('/experiment_split','development/evaluation/pilot required')
    obj(case['generation'], ['series_id','conditions'], [], '/generation')
    text(case['generation']['series_id'],'/generation/series_id')
    if not isinstance(case['generation']['conditions'],dict):
        error('/generation/conditions','object required (unknown conditions may be empty)')
    a=case['artifact']
    obj(a,['artifact_id','apk_sha256'],[], '/artifact')
    text(a['artifact_id'],'/artifact/artifact_id')
    if a['apk_sha256'] is not None and (not isinstance(a['apk_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',a['apk_sha256'])):
        error('/artifact/apk_sha256','SHA-256 or null required')
    if not isinstance(case['documents'],list): error('/documents','array required')
    docs, copies, warnings = {}, {}, []
    for i,d in enumerate(case['documents']):
        path=f'/documents/{i}'
        obj(d,['document_id','kind','path','sha256','version','artifact_id','origin_type','responded_at','review'],['redacted_path'],path)
        for field in ('document_id','path','version'): text(d[field],path+'/'+field)
        if d['document_id'] in docs: error(path,'duplicate document ID')
        if d['kind'] not in ('request','explanation'): error(path+'/kind','invalid kind')
        if d['artifact_id'] != a['artifact_id']: error(path+'/artifact_id','different artifact','ARTIFACT_MISMATCH')
        if d['kind']=='explanation' and d['origin_type'] not in ('initial_response','posthoc_explanation','revision_response'):
            error(path+'/origin_type','invalid explanation origin')
        if d['kind']=='request' and d['origin_type'] is not None: error(path,'request origin_type must be null')
        if d['responded_at'] is not None: timestamp(d['responded_at'],path+'/responded_at')
        else: warnings.append({'code':'MISSING_METADATA','path':path+'/responded_at'})
        original=(base/d['path']).resolve()
        if original.stat().st_size > 100*1024**2: error(path,'document exceeds 100 MiB')
        if file_hash(original)!=d['sha256']: error(path+'/sha256','original hash mismatch','ARTIFACT_MISMATCH')
        contents=original.read_text(encoding='utf-8')
        obj(d['review'],['status','reviewer','reviewed_at'],[],path+'/review')
        if d['review']['status'] not in ('complete','partial','unknown'): error(path+'/review/status','invalid status')
        text(d['review']['reviewer'],path+'/review/reviewer'); timestamp(d['review']['reviewed_at'],path+'/review/reviewed_at')
        docs[d['document_id']]={'metadata':d,'text':contents}
        copies[d['document_id']]=original
        if 'redacted_path' in d:
            text(d['redacted_path'],path+'/redacted_path')
            redacted=(base/d['redacted_path']).resolve()
            if redacted.stat().st_size > 100*1024**2: error(path,'redacted file too large')
            copies[d['document_id']+'-redacted']=redacted
    if not any(d['metadata']['kind']=='request' for d in docs.values()): error('/documents','request original required')
    ids=set(); requirements={}
    for collection, idfield, kind in (('requirements','requirement_id','request'),('claims','claim_id','explanation')):
        values=case[collection]
        if not isinstance(values,list): error('/'+collection,'array required')
        for i,item in enumerate(values):
            path=f'/{collection}/{i}'
            required=[idfield,'source','domain','predicate','value','scope','confirmation']
            required += ['explicit'] if kind=='request' else ['speech_act','certainty','requirement_ids']
            obj(item,required,[],path)
            text(item[idfield],path+'/'+idfield)
            if item[idfield] in ids: error(path,'duplicate ID')
            ids.add(item[idfield])
            src=item['source']; obj(src,['document_id','start_line','end_line'],[],path+'/source')
            text(src['document_id'],path+'/source/document_id')
            doc=docs.get(src['document_id'])
            if not doc or doc['metadata']['kind']!=kind: error(path+'/source','wrong/missing document','BROKEN_REFERENCE')
            if any(type(src[k]) is not int for k in ('start_line','end_line')) or not 1<=src['start_line']<=src['end_line']<=len(doc['text'].splitlines()):
                error(path+'/source','invalid original line range','BROKEN_REFERENCE')
            confirmation=item['confirmation']; obj(confirmation,['reviewer','reviewed_at'],[],path+'/confirmation')
            text(confirmation['reviewer'],path+'/confirmation/reviewer'); timestamp(confirmation['reviewed_at'],path+'/confirmation/reviewed_at')
            if item['domain'] not in ('permissions','endpoints','sdk','behavior'): error(path+'/domain','unsupported domain')
            if item['scope'] not in ('exact','general'): error(path+'/scope','exact/general required')
            allowed = {'permissions': ('allowlist',) if kind=='request' else ('present','absent'),
                       'endpoints': ('allowlist',) if kind=='request' else ('present','absent'),
                       'sdk': ('denylist',) if kind=='request' else ('present','absent'), 'behavior': ('runtime',)}
            if item['predicate'] not in allowed[item['domain']]: error(path+'/predicate','unsupported predicate','UNSUPPORTED_PREDICATE')
            value=item['value']
            if kind=='request':
                if type(item['explicit']) is not bool: error(path+'/explicit','boolean required')
                if item['domain']!='behavior' and not isinstance(value,list): error(path+'/value','array required')
                requirements[item[idfield]]=item
            else:
                if item['speech_act'] not in ('implemented','proposal','planned','example'): error(path+'/speech_act','invalid speech act')
                if item['certainty'] not in ('asserted','possible','uncertain'): error(path+'/certainty','invalid certainty')
                if not isinstance(item['requirement_ids'],list) or any(not isinstance(x,str) for x in item['requirement_ids']): error(path+'/requirement_ids','string array required')
                if item['domain']!='behavior': text(value,path+'/value')
            vals=value if isinstance(value,list) else [value]
            if item['domain']=='endpoints':
                if kind=='request':
                    for v in vals:
                        obj(v,['host','include_subdomains'],[],path+'/value')
                        try:
                            normalized=host(v['host'])
                        except (ValueError,UnicodeError): error(path+'/value','invalid host')
                        if normalized!=v['host'] or type(v['include_subdomains']) is not bool: error(path+'/value','canonical host and boolean required')
                        from .validation import is_ip
                        if is_ip(normalized) and v['include_subdomains']: error(path+'/value','IP cannot include subdomains')
                else:
                    from .adapter import normalize_url
                    try: normalize_url(value)
                    except (ValueError,UnicodeError): error(path+'/value','HTTP(S) URL required')
            elif item['domain']=='sdk':
                registered={r['sdk_id'] for r in REGISTRY['rules']}
                if any(not isinstance(v,str) or v not in registered for v in vals): error(path+'/value','SDK not in fixed registry')
            elif item['domain']=='permissions':
                if any(not isinstance(v,str) or not re.fullmatch(r'[\w]+(?:\.[\w]+)+',v) for v in vals): error(path+'/value','fully qualified permission required')
            else: text(value,path+'/value')
    for item in case['claims']:
        if any(r not in requirements for r in item['requirement_ids']): error('/claims/requirement_ids','missing requirement','BROKEN_REFERENCE')
    return docs,copies,warnings
