import argparse
import datetime as dt
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tempfile
import time
import uuid
from . import __version__
from .adapter import ADAPTER_VERSION
from .report_validation import validate_report
from .comparison import compare
from .extractor import extract, LIMITS, inspect_apk
from .http_policy import SUPPORT_MATRIX
from .matcher import match_report, RULE_VERSION, REGISTRY_HASH
from .reporting import dump, output_transaction, write_result, code
from .validation import CheckError, load_json, validate_intent, file_hash, digest


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def parser():
    p = argparse.ArgumentParser(description='開発意図とAPK静的証拠の照合（実通信・安全性は判定しません）')
    sub = p.add_subparsers(dest='command', required=True)
    for command in ('match', 'analyze', 'validate-intent'):
        c = sub.add_parser(command)
        c.add_argument('--intent', required=True)
        if command != 'validate-intent':
            c.add_argument('--case-id', required=True)
            c.add_argument('--out', required=True)
            c.add_argument('--config', help='JSON object containing resource_limits overrides')
            c.add_argument('--apk', required=command=='analyze')
            if command == 'match':
                c.add_argument('--static-report', required=True)
    c = sub.add_parser('compare')
    for f in ('before', 'after', 'episode-id', 'out'):
        c.add_argument('--'+f, required=True)
    c = sub.add_parser('join-reviews')
    for f in ('result', 'reviews', 'out'):
        c.add_argument('--'+f, required=True)
    return p


def execute(args):
    started = now()
    t = time.monotonic()
    if args.command == 'compare':
        before, after = load_json(args.before), load_json(args.after)
        try:
            result = compare(before, after, args.episode_id)
        except (KeyError, TypeError, ValueError) as e:
            raise CheckError('INCOMPARABLE_RUNS', 'invalid result structure: '+str(e)) from e
        with output_transaction(args.out) as out:
            dump(out/'comparison.json', result)
            (out/'comparison.md').write_text('# 修正前後比較\n\n'+code(json.dumps(result, ensure_ascii=False, indent=2))+'\n', encoding='utf-8')
        return 3 if result['partial'] else 0
    if args.command == 'join-reviews':
        result, reviews = load_json(args.result), load_json(args.reviews)
        ids = {f['finding_id'] for f in result['findings']}
        if not isinstance(reviews, list) or any(not isinstance(r, dict) or r.get('finding_id') not in ids or r.get('run_id') != result['run_id'] for r in reviews):
            raise CheckError('INVALID_REVIEW', 'each review must reference this run_id and an existing finding_id')
        with output_transaction(args.out) as out:
            dump(out/'reviews.json', {'run_id': result['run_id'], 'result_sha256': file_hash(args.result), 'reviews': reviews})
        return 0
    if args.command in ('match', 'analyze') and args.config:
        config = load_json(args.config)
        if not isinstance(config, dict) or set(config) != {'resource_limits'} or not isinstance(config['resource_limits'], dict):
            raise CheckError('INVALID_CONFIG', 'config must contain only a resource_limits object')
        for name, value in config['resource_limits'].items():
            if name not in LIMITS or type(value) is not int or value <= 0:
                raise CheckError('INVALID_CONFIG', 'unknown resource limit or nonpositive integer: '+name)
        LIMITS.update(config['resource_limits'])
        from . import validation
        validation.JSON_LIMIT = LIMITS['json_bytes']
    source_intent = load_json(args.intent)
    intent, warnings = validate_intent(source_intent)
    if args.command == 'validate-intent':
        print(json.dumps({'status': 'valid', 'normalized_intent': intent, 'warnings': warnings}, ensure_ascii=False, indent=2))
        return 0
    if Path(args.out).exists():
        raise CheckError('OUTPUT_EXISTS', 'output already exists: '+args.out)
    with tempfile.TemporaryDirectory(prefix='intentcheck-') as work:
        if args.command == 'analyze':
            report = extract(args.apk, work)
            source_bytes = (json.dumps(report, ensure_ascii=False, indent=2)+'\n').encode()
        else:
            report = load_json(args.static_report)
            source_bytes = Path(args.static_report).read_bytes()
        validate_report(report)
        if not isinstance(report, dict) or not isinstance(report.get('application'), dict):
            raise CheckError('UNSUPPORTED_SCHEMA', 'application object required')
        application = dict(report['application'])
        sha = application.get('sha256')
        if sha is not None and (not isinstance(sha, str) or len(sha) != 64 or any(c not in '0123456789abcdefABCDEF' for c in sha)):
            raise CheckError('UNSUPPORTED_SCHEMA', 'invalid APK sha256')
        if args.apk:
            inspect_apk(args.apk)
            actual = file_hash(args.apk)
            if not sha or sha.lower() != actual:
                raise CheckError('APK_HASH_MISMATCH', 'APK hash missing or differs from report')
            application['sha256'] = actual
            application['identity_verification'] = 'apk_verified'
        else:
            application['identity_verification'] = 'report_only'
        if not sha:
            warnings.append({'code': 'MISSING_EVIDENCE', 'path': '/application/sha256', 'message': 'APK identity hash missing in source report'})
        facts, findings, summaries = match_report(intent, report)
        partial = any(s['has_unknowns'] for s in summaries.values())
        run_id = 'R-'+uuid.uuid4().hex
        provenance = {'adapter': ADAPTER_VERSION, 'tool_versions': {'intentcheck': __version__, 'python': platform.python_version()},
                      'rule_version': RULE_VERSION, 'registry_hash': REGISTRY_HASH,
                      'extractor_version': 'bounded-1.0' if args.command=='analyze' else 'report-import-1.0',
                      'source_report_sha256': digest(source_bytes), 'http_support_matrix': SUPPORT_MATRIX,
                      'tool_fingerprints': report.get('intentcheck_extraction', {}).get('tool_fingerprints', {})}
        result = {'result_schema_version': '1.0', 'run_id': run_id, 'case_id': args.case_id,
                  'application': application,
                  'intent': {'id': intent['intent_id'], 'version': intent['intent_version'],
                             'sha256': file_hash(args.intent), 'recorded_at': intent['recorded_at'], 'snapshot': source_intent},
                  'provenance': provenance, 'stages': facts.pop('stages'), 'facts': facts,
                  'findings': findings, 'summaries': summaries,
                  'errors': [{'code':'PARTIAL_EXTRACTION', 'stage': d, 'message':'必要な証拠・走査範囲が不足'} for d,s in summaries.items() if s['has_unknowns']],
                  'warnings': warnings+facts.pop('warnings')}
        import resource
        run = {'run_id': run_id, 'started_at': started, 'finished_at': now(), 'elapsed_seconds': time.monotonic()-t,
               'peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
               'child_peak_rss_kib': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
               'os': platform.platform(), 'python': platform.python_version(), 'argv': sys.argv[1:],
               'limits': LIMITS, 'provenance': provenance, 'intent_sha256': file_hash(args.intent),
               'apk_sha256': application.get('sha256'), 'apk_size_bytes': Path(args.apk).stat().st_size if args.apk else None,
               'outcome': 'partial' if partial else 'complete'}
        with output_transaction(args.out) as out:
            write_result(out, result, run, source_bytes)
        print(f'{run_id}: '+('partial' if partial else 'complete')+f'; results: {out}')
        return 3 if partial else 0


def main():
    args = parser().parse_args()
    try:
        return execute(args)
    except CheckError as e:
        print(json.dumps({'code': e.code, 'message': str(e)}, ensure_ascii=False), file=sys.stderr)
        return e.exit_code
    except Exception as e:
        print(json.dumps({'code': 'EXECUTION_ERROR', 'message': str(e)}, ensure_ascii=False), file=sys.stderr)
        return 4


if __name__ == '__main__':
    raise SystemExit(main())
