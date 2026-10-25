"""v2 CLI orchestration. Original text is data, never executable instructions."""
import csv
import datetime as dt
import json
from pathlib import Path
import platform
import shutil
import tempfile
import time
from .adapter import ADAPTER_VERSION
from .extractor import extract, inspect_apk, LIMITS
from .validation import CheckError, load_json, file_hash, digest
from .triad_input import validate_case
from .triad_match import match, RULE_VERSION
from .sdk import scan_sdk, REGISTRY, REGISTRY_HASH
from .reporting import output_transaction, dump, code

LABELS={'mismatch':'要求との不一致','conform_in_scope':'確認範囲で適合','needs_review':'追加確認が必要',
        'unspecified':'方針未指定','unknown':'判定不能','out_of_scope':'対象外',
        'supported_in_scope':'確認範囲で裏付けあり','contradicted':'説明と証拠が矛盾',
        'insufficient_evidence':'裏付け不足','not_asserted':'実装済みの主張ではない',
        'explanation_unavailable':'説明未提供','covered':'説明対応あり','partially_covered':'部分対応',
        'omission_candidate':'説明漏れ候補','ambiguous':'対応が曖昧','not_evaluable':'説明対応を評価できない'}


def report_text(result, baseline=False):
    lines=['# 三者照合 '+('基準一覧' if baseline else '構成説明・確認事項'),'',
           '実通信・総合安全性は判定しません。原文・証拠は両表示で同一です。','',
           '対象: '+code(result['artifact']), '解析範囲: '+code(result['stages']),
           '未確認範囲あり: '+str(result['has_unknowns']),
           '研究評価への使用: '+('検証済みAPKケース' if result['evaluation_eligible'] else '未検証。評価対象に組み入れない'),
           '', '構成概要: '+code(result['configurations']), '', '項目別要約: '+code(result['summary'])]
    for d in result['case']['documents']:
        lines+=['', '原文参照: '+code(d)]
    all_inputs=result['case']['requirements']+result['case']['claims']
    items={x.get('requirement_id',x.get('claim_id')):x for x in all_inputs}
    if baseline:
        selected=result['findings']
    else:
        priority={'mismatch':0,'contradicted':1,'omission_candidate':2}
        selected=sorted(result['findings'],key=lambda f:priority.get(f['verdict'],3))
    for f in selected:
        lines+=['','## '+f['finding_id']+' '+LABELS[f['verdict']],
                '', '開発要求: '+code([items[r] for r in f['requirement_ids']]),
                '', 'AIの説明: '+code([items[c] for c in f['claim_ids']]),
                '', '確認した事実: '+code([c for c in result['configurations'] if c['configuration_id'] in f['configuration_ids']]),
                '', '判定と理由: '+code(f), '', '根拠の場所: '+code([e for e in result['facts']['evidence'] if e['evidence_id'] in f['evidence_ids']]),
                '', '次に確認すること: '+code(f['next_check']), '', 'わからないこと: '+code(f['limitations'])]
    lines+=['','## 全証拠（両表示で同一）','',code(result['facts']['evidence'])]
    return '\n'.join(lines)+'\n'


def imported_sdk(report):
    sdk=report.get('triad_sdk')
    if sdk is None:
        return {'registry':REGISTRY,'registry_hash':REGISTRY_HASH,'entries':[],
                'stage':{'status':'not_run','coverage':'unknown','scope':REGISTRY['scope'],'errors':['SDK構造証拠は元レポートに含まれない']}}
    if not isinstance(sdk,dict) or sdk.get('registry_hash')!=REGISTRY_HASH or sdk.get('registry')!=REGISTRY:
        raise CheckError('UNSUPPORTED_SCHEMA','/triad_sdk: SDK registry mismatch')
    if not isinstance(sdk.get('stage'),dict) or not isinstance(sdk.get('entries'),list):
        raise CheckError('UNSUPPORTED_SCHEMA','/triad_sdk: stage/entries invalid')
    if sdk['stage'].get('status') not in ('success','partial','failed','unsupported','not_run') or sdk['stage'].get('coverage') not in ('complete_in_scope','partial','unknown'):
        raise CheckError('UNSUPPORTED_SCHEMA','/triad_sdk/stage: invalid status/coverage')
    rules={r['sdk_id']:r for r in REGISTRY['rules']}
    seen=set()
    for entry in sdk['entries']:
        if not isinstance(entry,dict) or not isinstance(entry.get('sdk_id'),str) or entry.get('sdk_id') not in rules or entry.get('strength') not in ('sdk_signature','embedded_string') or not isinstance(entry.get('classes'),dict) or not isinstance(entry.get('hint_members'),list):
            raise CheckError('UNSUPPORTED_SCHEMA','/triad_sdk/entries: invalid SDK evidence')
        if entry['sdk_id'] in seen or any(not isinstance(entry.get(k),str) for k in ('name','category')) or any(not isinstance(v,str) for v in entry['hint_members']):
            raise CheckError('UNSUPPORTED_SCHEMA','/triad_sdk/entries: duplicate SDK or invalid metadata')
        if not entry['classes'] and not entry['hint_members']:
            raise CheckError('UNSUPPORTED_SCHEMA','/triad_sdk/entries: missing evidence')
        seen.add(entry['sdk_id'])
        for name,locs in entry['classes'].items():
            if name not in rules[entry['sdk_id']]['required_classes'] or not isinstance(locs,list) or not locs or any(not isinstance(l,dict) or not isinstance(l.get('apk_member'),str) or not isinstance(l.get('locator'),str) for l in locs):
                raise CheckError('UNSUPPORTED_SCHEMA','/triad_sdk/entries/classes: invalid locations')
        if entry['strength']=='sdk_signature' and set(entry['classes'])!=set(rules[entry['sdk_id']]['required_classes']):
            raise CheckError('UNSUPPORTED_SCHEMA','/triad_sdk/entries: incomplete signature')
    return sdk


def run(args):
    started=dt.datetime.now(dt.timezone.utc).isoformat(); t=time.monotonic()
    if args.config:
        config=load_json(args.config)
        if not isinstance(config,dict) or set(config)!={'resource_limits'} or not isinstance(config['resource_limits'],dict):
            raise CheckError('INVALID_INPUT','config must contain a resource_limits object')
        for k,v in config['resource_limits'].items():
            if k not in LIMITS or type(v) is not int or v<=0: raise CheckError('INVALID_INPUT','invalid resource limit: '+k)
        LIMITS.update(config['resource_limits'])
        from . import validation
        validation.JSON_LIMIT=LIMITS['json_bytes']
    case_path=Path(args.case).resolve(); case=load_json(case_path)
    docs,copies,warnings=validate_case(case,case_path.parent)
    with tempfile.TemporaryDirectory(prefix='triad-') as work:
        if args.static_report:
            report=load_json(args.static_report)
        elif args.apk:
            try:
                report=extract(args.apk,work)
            except CheckError as failure:
                if failure.code not in ('TOOL_TIMEOUT','TOOL_FAILED'):
                    raise
                # Independent SDK evidence can still be obtained without inventing
                # missing Manifest/URL facts after an external extractor failure.
                report={'schema_version':'1.0','application':{'sha256':file_hash(args.apk)},
                        'stages':{'extractor':{'status':'failed','coverage':'unknown','errors':[failure.code]}}}
                warnings.append({'code':failure.code,'stage':'extractor'})
        else: raise CheckError('INVALID_INPUT','--apk or --static-report required')
        if not isinstance(report,dict) or not isinstance(report.get('application'),dict): raise CheckError('UNSUPPORTED_SCHEMA','application required')
        app=report['application']; recorded=app.get('sha256'); expected=case['artifact']['apk_sha256']
        if expected and recorded and expected.lower()!=str(recorded).lower(): raise CheckError('ARTIFACT_MISMATCH','case and static report hashes differ')
        if args.apk:
            inspect_apk(args.apk); actual=file_hash(args.apk)
            if not recorded or str(recorded).lower()!=actual or expected and expected!=actual: raise CheckError('ARTIFACT_MISMATCH','APK and report/case hashes differ')
            sdk=scan_sdk(args.apk,LIMITS['member_bytes']); report['triad_sdk']=sdk
            verification='apk_verified'
        else:
            sdk=imported_sdk(report); verification='report_only' if recorded and expected else 'unverified'
        result=match(case,report,sdk)
        source=(json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
        result.update(result_schema_version='2.0',case=case,case_id=case['case_id'],
                      artifact=dict(case['artifact'],application=app,identity_verification=verification),
                      evaluation_eligible=verification=='apk_verified' and bool(expected),
                      warnings=warnings+([] if any(d['kind']=='explanation' for d in case['documents']) else [{'code':'MISSING_EXPLANATION'}]),
                      provenance={'adapter':ADAPTER_VERSION,'rule_version':RULE_VERSION,'sdk_registry_hash':REGISTRY_HASH,
                                  'case_sha256':file_hash(case_path),'source_report_sha256':digest(source),
                                  'input_static_report_sha256':file_hash(args.static_report) if args.static_report else None,
                                  'implementation_hashes':{p.name:file_hash(p) for p in sorted(Path(__file__).parent.glob('*.py'))},
                                  'input_hashes':{d['document_id']:d['sha256'] for d in case['documents']}},
                      units={'apk_count':1,'requirement_count':len(case['requirements']),'claim_count':len(case['claims']),
                             'configuration_count':len(result['configurations']),'finding_count':len(result['findings'])})
        # Stable result ID: timestamps are confined to run.json.
        result['run_id']='T-'+digest(json.dumps(result,ensure_ascii=False,sort_keys=True).encode())[:20]
        with output_transaction(args.out) as out:
            dump(out/'result.json',result)
            dump(out/'run.json',{'run_id':result['run_id'],'started_at':started,'elapsed_seconds':time.monotonic()-t,
                                'python':platform.python_version(),'platform':platform.platform(),'limits':LIMITS,'provenance':result['provenance']})
            raw=out/'raw_inputs'; raw.mkdir()
            dump(raw/'case.json',case); (raw/'source_static_analysis.json').write_bytes(source)
            if args.static_report:
                shutil.copyfile(args.static_report,raw/'original_static_analysis.json')
            for number,(key,path) in enumerate(sorted(copies.items())):
                # Never interpret document IDs as filesystem paths.
                shutil.copyfile(path,raw/f'document-{number}.txt')
            dump(raw/'manifest.json',{key:{'copy':f'document-{i}.txt','sha256':file_hash(path)} for i,(key,path) in enumerate(sorted(copies.items()))})
            (out/'report.md').write_text(report_text(result),encoding='utf-8')
            (out/'baseline.md').write_text(report_text(result,True),encoding='utf-8')
            dump(out/'case.json',{'case_id':case['case_id'],'run_id':result['run_id'],'units':result['units'],'artifact':result['artifact'],'evaluation_eligible':result['evaluation_eligible']})
            with (out/'findings.csv').open('w',encoding='utf-8',newline='') as stream:
                fields=['case_id','finding_id','axis','domain','verdict','requirement_ids','claim_ids','configuration_ids','evidence_ids','rule_id','rule_version','reason']
                writer=csv.DictWriter(stream,fieldnames=fields); writer.writeheader()
                for f in result['findings']:
                    row={k:case['case_id'] if k=='case_id' else f[k] for k in fields}
                    writer.writerow({k:csv_value(v) for k,v in row.items()})
            dump(out/'evaluation_units.json',{'evaluation_eligible':result['evaluation_eligible'],'units':result['units'],
                 'rows':[{k:f[k] for k in ('finding_id','axis','domain','verdict','requirement_ids','claim_ids','configuration_ids')} for f in result['findings']]})
        return 3 if result['has_unknowns'] else 0


def csv_value(value):
    v=json.dumps(value,ensure_ascii=False) if isinstance(value,(list,dict)) else str(value)
    return "'"+v if v.lstrip().startswith(('=','+','-','@')) else v
