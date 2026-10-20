import csv
import json
from pathlib import Path
from .validation import CheckError

LABELS = {'mismatch': '不一致を確認', 'candidate': '不一致候補', 'unknown': '確認不能',
          'conform_in_scope': '確認範囲で適合', 'unspecified': '未指定'}


def dump(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)+'\n', encoding='utf-8')


def new_output(path):
    p = Path(path)
    try:
        p.mkdir(parents=True, exist_ok=False)
    except FileExistsError as e:
        raise CheckError('OUTPUT_EXISTS', 'output directory already exists: '+str(p)) from e
    return p


def code(value):
    # Render evidence as escaped plain text; never let APK strings become raw HTML/links.
    return str(value).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('|','&#124;').replace('`','&#96;').replace('\n','<br>').replace('[','&#91;').replace(']','&#93;')


def write_result(out, result, run, source_bytes):
    dump(out/'result.json', result)
    dump(out/'run.json', run)
    (out/'source_static_analysis.json').write_bytes(source_bytes)
    lines = ['# 開発意図照合レポート', '', f'実行: {result["run_id"]} / ケース: {code(result["case_id"])}',
             f'対象: {code(result["application"])}', f'意図: {code(result["intent"]["id"])} / {code(result["intent"]["version"])}',
             '', '## 項目別要約', '', '| 項目 | 判定 | 未確認範囲 |', '|---|---|---|']
    for domain, s in result['summaries'].items():
        lines.append(f'| {domain} | {LABELS[s["verdict"]]} | {s["has_unknowns"]} |')
    for verdict in LABELS:
        selected = [f for f in result['findings'] if f['verdict'] == verdict]
        if not selected:
            continue
        lines.extend(['', '## '+LABELS[verdict]])
        for f in selected:
            lines.extend(['', '### '+f['finding_id'], '', '入力した要求: '+code(f['intent_text']),
                          '', '抽出事実: '+code(json.dumps(f['fact'], ensure_ascii=False)),
                          '', '判定理由: '+code(f['reason']), '', '証拠ID: '+code(f['evidence_ids']),
                          '', '確認範囲: '+code(f['scope']), '', '限界: '+code(f['limitations'])])
    lines.extend(['', '## 証拠一覧・解析範囲・エラー', ''])
    for e in result['facts']['evidence']:
        lines.append(f'- {e["evidence_id"]}: '+code(json.dumps(e, ensure_ascii=False)))
    lines.extend(['', code(json.dumps(result['stages'], ensure_ascii=False)), '', code(result['errors']), '', code(result['warnings'])])
    (out/'report.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    fields = 'run_id case_id apk_sha256 intent_id intent_version domain requirement_id rule_id rule_version finding_id verdict fact_json evidence_ids_json reason scope limitations_json has_unknowns'.split()
    with (out/'findings.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for f in result['findings']:
            row = {k: f.get(k, '') for k in fields}
            row.update(run_id=result['run_id'], case_id=result['case_id'], apk_sha256=result['application'].get('sha256'),
                       intent_id=result['intent']['id'], intent_version=result['intent']['version'],
                       fact_json=json.dumps(f['fact'], ensure_ascii=False), evidence_ids_json=json.dumps(f['evidence_ids']),
                       limitations_json=json.dumps(f['limitations'], ensure_ascii=False),
                       has_unknowns=result['summaries'][f['domain']]['has_unknowns'])
            writer.writerow({k: "'"+v if isinstance(v, str) and v.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')) else v for k,v in row.items()})
    dump(out/'case.json', {k: result[k] for k in ('case_id','run_id','application','intent','provenance')})
