import copy
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from intentcheck.validation import CheckError, load_json, validate_intent, host
from intentcheck.adapter import adapt, normalize_url
from intentcheck.matcher import match_report
from intentcheck.http_policy import evaluate_http, ANDROID
from intentcheck.comparison import compare
from intentcheck.extractor import extract, inspect_apk

ROOT = Path(__file__).resolve().parent.parent


def intent():
    return json.loads((ROOT/'examples/intentcheck/intent.json').read_text())


def report(permissions=None, urls=None, complete=True):
    return {'schema_version': '1.0', 'application': {'package_name': 'test.app', 'sha256': 'a'*64},
            'permissions': [{'name': p} for p in (permissions or [])],
            'findings': [{'signal_type':'url', 'value':u, 'evidence':'source_file=classes.dex'} for u in (urls or [])],
            'stages': {'manifest_badging_analysis': {'status':'success'}},
            'intentcheck_extraction': {'version':'1.0', 'stages': {d: {'status':'success' if complete else 'partial',
                       'coverage':'complete_in_scope' if complete else 'partial'} for d in ('permissions','endpoints')}}}


def run_result(r):
    p = intent()
    f, findings, summaries = match_report(p, r)
    return {'result_schema_version': '1.0', 'run_id': 'test', 'facts': f, 'findings': findings,
            'summaries': summaries, 'intent': {'id':'i','version':'1','sha256':'same'},
            'application': r['application'], 'provenance': {'adapter':'1','rule_version':'1','registry_hash':'same'}}


class ValidationTest(unittest.TestCase):
    def test_strict_fields(self):
        for field, value in [('intent_version',None),('permissions',{'mode':'unspecified','allowed':[]}),
                             ('endpoints',{'mode':'allowlist','allowed_hosts':[{'host':'*.example.com','include_subdomains':True}]}),
                             ('recorded_at','2026-10-20T10:00:00'),('sdk_inclusion',{'mode':'denylist','denied_sdk_ids':['unknown'],'registry_version':'trafficissue-hints-1'})]:
            with self.subTest(field=field):
                x=intent(); x[field]=value
                with self.assertRaises(CheckError): validate_intent(x)
        x=intent(); x['typo']=True
        with self.assertRaises(CheckError): validate_intent(x)

    def test_duplicates(self):
        x=intent(); x['permissions']['allowed'] *= 2
        normalized,warnings=validate_intent(x)
        self.assertEqual(len(normalized['permissions']['allowed']),1)
        self.assertEqual(len(warnings),1)
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'x'; p.write_text('{"a":1,"a":2}')
            with self.assertRaises(CheckError): load_json(p)

    def test_host_parsing(self):
        self.assertEqual(host('API.Example.com.'),'api.example.com')
        self.assertEqual(host('2001:0db8::1'),'2001:db8::1')
        self.assertTrue(host('例え.jp').startswith('xn--'))
        for bad in ('https://x.test','x.test:80','x.test/a','x..test'):
            with self.assertRaises(ValueError): host(bad)


class MatcherTest(unittest.TestCase):
    def test_permission_acceptance(self):
        p=intent()
        for names, complete, expected in [(['android.permission.READ_CONTACTS'],True,'mismatch'),
                                         (['android.permission.INTERNET'],True,'conform_in_scope'),
                                         (['android.permission.READ_CONTACTS'],False,'mismatch')]:
            f, findings, s=match_report(p,report(names,complete=complete))
            self.assertEqual(s['permissions']['verdict'],expected)
            self.assertEqual(s['permissions']['has_unknowns'],not complete)
        r=report(); del r['permissions']
        self.assertEqual(match_report(p,r)[2]['permissions']['verdict'],'unknown')
        p['permissions']={'mode':'unspecified'}
        self.assertEqual(match_report(p,r)[2]['permissions']['verdict'],'unspecified')
        p['permissions']={'mode':'allowlist','allowed':[]}
        self.assertEqual(match_report(p,report(['android.permission.INTERNET']))[2]['permissions']['verdict'],'mismatch')

    def test_urls_boundary_userinfo_subdomains(self):
        p=intent()
        for url, sub, expected in [('https://api.example.com.evil.test/a',False,'candidate'),
                                  ('https://api.example.com@evil.test/a',False,'candidate'),
                                  ('https://x.api.example.com/a',False,'candidate'),
                                  ('https://x.api.example.com/a',True,'conform_in_scope'),
                                  ('https://api.example.com:8443/path',False,'conform_in_scope')]:
            with self.subTest(url=url):
                p['endpoints']['allowed_hosts'][0]['include_subdomains']=sub
                self.assertEqual(match_report(p,report(urls=[url]))[2]['endpoints']['verdict'],expected)
        self.assertEqual(normalize_url('https://API.example.com/a#one'),normalize_url('https://api.example.com:443/a#two'))

    def test_dedup_namespaces_reference(self):
        r=report(urls=['https://evil.test/a','https://evil.test/a'])
        r['dynamic_analysis_handoff']={'expected_urls':['https://evil.test/a']}
        f=adapt(r)
        self.assertEqual(len(f['url_candidates']),1)
        self.assertEqual(len(f['url_candidates'][0]['evidence_ids']),2)
        ext=r['intentcheck_extraction']; ext['url_occurrences']=[
            {'value':'http://schemas.android.com/apk/res/android','role':'xml_namespace','method':'xml_namespace_declaration','apk_member':'AndroidManifest.xml'},
            {'value':'http://schemas.android.com/apk/res/android','apk_member':'classes.dex'},
            {'value':'https://docs.example.com/guide','apk_member':'assets/a.txt'}]
        f=adapt(r)
        self.assertEqual(len(f['excluded_occurrences']),1)
        self.assertEqual(len(f['url_candidates']),2)

    def test_legacy_success_is_not_complete(self):
        r=report(); del r['intentcheck_extraction']
        s=match_report(intent(),r)[2]
        self.assertEqual(s['permissions']['verdict'],'unknown')
        self.assertEqual(s['endpoints']['verdict'],'unknown')
        self.assertEqual(s['cleartext_configuration']['verdict'],'unknown')

    def test_sdk_not_absent(self):
        p=intent(); p['sdk_inclusion']={'mode':'denylist','denied_sdk_ids':['google_ads'],'registry_version':'trafficissue-hints-1'}
        self.assertEqual(match_report(p,report())[2]['sdk_inclusion']['verdict'],'unknown')
        r=report(); r['sdk_metadata']={'AdMob':{'id':'google_ads'}}; r['sdk_hints']={'AdMob':['com.google.android.gms.ads']}
        self.assertEqual(match_report(p,r)[2]['sdk_inclusion']['verdict'],'candidate')
        p['sdk_inclusion']['denied_sdk_ids']=[]
        self.assertEqual(match_report(p,r)[2]['sdk_inclusion']['verdict'],'conform_in_scope')


class HttpTest(unittest.TestCase):
    def config(self, attributes='', nsc=None, target=35):
        return {'manifest_xml': f'<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-sdk android:targetSdkVersion="{target}"/><application {attributes}/></manifest>',
                'nsc_xml':nsc, 'resource_resolution':'resolved_default','resource_variants':[]}

    def test_defaults_and_manifest(self):
        self.assertEqual(evaluate_http(self.config(),35,'default')['verdict'],'conform_in_scope')
        self.assertEqual(evaluate_http(self.config(target=27),35,'default')['verdict'],'mismatch')
        self.assertEqual(evaluate_http(self.config('android:usesCleartextTraffic="true"'),35,'default')['verdict'],'mismatch')
        self.assertEqual(evaluate_http(self.config(),36,'default')['verdict'],'unknown')

    def test_nsc_priority_inheritance(self):
        c=self.config('android:usesCleartextTraffic="true" android:networkSecurityConfig="@xml/net"',
                      '<network-security-config><base-config cleartextTrafficPermitted="false"/><domain-config><domain>example.com</domain><domain-config cleartextTrafficPermitted="true"><domain>sub.example.com</domain></domain-config></domain-config></network-security-config>')
        r=evaluate_http(c,35,'default'); self.assertEqual(r['verdict'],'mismatch')
        self.assertFalse(r['ranges'][1]['allowed']); self.assertTrue(r['ranges'][2]['allowed'])
        c['nsc_xml']='<network-security-config><base-config cleartextTrafficPermitted="false"/></network-security-config>'
        self.assertEqual(evaluate_http(c,35,'default')['verdict'],'conform_in_scope')
        self.assertEqual(evaluate_http(c,23,'default')['verdict'],'mismatch')
        c['resource_variants']=['res/xml-v28/net.xml']
        self.assertEqual(evaluate_http(c,35,'default')['verdict'],'unknown')

    def test_unknown_environment_prevents_summary_conformity(self):
        p=intent(); p['cleartext_configuration']['runtime_api_levels']=[35,36]
        r=report(); r['intentcheck_extraction']['http_configuration']=self.config()
        self.assertEqual(match_report(p,r)[2]['cleartext_configuration']['verdict'],'unknown')


class ComparisonTest(unittest.TestCase):
    def test_new_and_unknown_and_failed_after(self):
        before=run_result(report())
        after=run_result(report(['android.permission.READ_CONTACTS']))
        self.assertEqual(compare(before,after,'E')['relations'][0]['relation'],'new_mismatch')
        before=run_result(report(complete=False))
        self.assertEqual(compare(before,after,'E')['relations'][0]['relation'],'comparison_unknown')
        failed=run_result(report(complete=False))
        c=compare(after,failed,'E')
        self.assertEqual(c['relations'][0]['relation'],'comparison_unknown')
        self.assertEqual(c['facts'][0]['change'],'unknown')
        failed['intent']['sha256']='different'
        with self.assertRaises(CheckError): compare(after,failed,'E')


class CLITest(unittest.TestCase):
    def cli(self,*args):
        return subprocess.run([sys.executable,'-m','intentcheck',*map(str,args)],cwd=ROOT,capture_output=True,text=True)

    def test_reports_identity_reproducibility_and_reviews(self):
        with tempfile.TemporaryDirectory() as t:
            t=Path(t); i=t/'intent.json'; r=t/'static.json'
            p=intent(); p['cleartext_configuration']={'mode':'unspecified'}
            i.write_text(json.dumps(p)); r.write_text(json.dumps(report(['android.permission.READ_CONTACTS'],['https://evil.test/a'])))
            for run in ('one','two'):
                c=self.cli('match','--intent',i,'--static-report',r,'--case-id','=C1','--out',t/run)
                self.assertEqual(c.returncode,0,c.stderr)
            one=load_json(t/'one/result.json'); two=load_json(t/'two/result.json')
            self.assertEqual(one['findings'],two['findings'])
            self.assertEqual(one['summaries'],two['summaries'])
            ids={e['evidence_id'] for e in one['facts']['evidence']}
            for f in one['findings']: self.assertTrue(set(f['evidence_ids'])<=ids)
            with (t/'one/findings.csv').open() as stream:
                rows=list(csv.DictReader(stream))
            self.assertEqual([r['verdict'] for r in rows],[f['verdict'] for f in one['findings']])
            self.assertEqual(rows[0]['case_id'],"'=C1")
            c=self.cli('match','--intent',i,'--static-report',r,'--case-id','C','--out',t/'one')
            self.assertEqual(c.returncode,2)
            rev=t/'rev.json'; rev.write_text(json.dumps([{'run_id':one['run_id'],'finding_id':one['findings'][0]['finding_id'],'note':'確認中'}]))
            c=self.cli('join-reviews','--result',t/'one/result.json','--reviews',rev,'--out',t/'review')
            self.assertEqual(c.returncode,0,c.stderr)
            apk=t/'a.apk'
            with zipfile.ZipFile(apk,'w') as z: z.writestr('AndroidManifest.xml','<manifest/>')
            c=self.cli('match','--intent',i,'--static-report',r,'--apk',apk,'--case-id','C','--out',t/'bad')
            self.assertEqual(c.returncode,2); self.assertIn('APK_HASH_MISMATCH',c.stderr)
            self.assertFalse((t/'bad').exists())

    def test_analyze_fixture_and_safe_archive(self):
        with tempfile.TemporaryDirectory() as t:
            t=Path(t); apk=t/'app.apk'
            xml='<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.app"><uses-sdk android:targetSdkVersion="35"/><uses-permission android:name="android.permission.READ_CONTACTS"/><permission android:name="test.app.DEFINED"/><application android:usesCleartextTraffic="false"/></manifest>'
            with zipfile.ZipFile(apk,'w') as z:
                z.writestr('AndroidManifest.xml',xml)
                z.writestr('assets/urls.txt','https://evil.test/a https://api.example.com/ok')
            c=self.cli('analyze','--intent',ROOT/'examples/intentcheck/intent.json','--apk',apk,'--case-id','fixture','--out',t/'run')
            self.assertEqual(c.returncode,0,c.stderr+c.stdout)
            result=load_json(t/'run/result.json')
            self.assertEqual(result['summaries']['permissions']['verdict'],'mismatch')
            self.assertEqual(result['summaries']['cleartext_configuration']['verdict'],'conform_in_scope')
            self.assertEqual(len(result['facts']['permissions']),1)
            self.assertEqual(result['application']['identity_verification'],'apk_verified')
            bad=t/'bad.apk'
            with zipfile.ZipFile(bad,'w') as z:
                z.writestr('AndroidManifest.xml',xml); z.writestr('../escape','x')
            with self.assertRaises(CheckError): inspect_apk(bad)

class FailureBoundariesTest(unittest.TestCase):
    def test_unknown_schema_and_missing_fields(self):
        for r in ({}, {'schema_version':'9','application':{},'stages':{}}, {'schema_version':'1.0','application':{},'stages':{},'permissions':None}):
            with self.assertRaises(CheckError): adapt(r)
        r=report(); r['findings']=[{'signal_type':'url','value':'https://[invalid'}]
        self.assertFalse(adapt(r)['coverage']['endpoints'])

    def test_missing_nsc_and_reference_booleans(self):
        xml='<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-sdk android:targetSdkVersion="35"/><application android:networkSecurityConfig="@xml/n"/></manifest>'
        self.assertEqual(evaluate_http({'manifest_xml':xml},35,'default')['verdict'],'unknown')
        xml=xml.replace('android:networkSecurityConfig="@xml/n"','android:usesCleartextTraffic="@bool/allow"')
        self.assertEqual(evaluate_http({'manifest_xml':xml},35,'default')['verdict'],'unknown')
        self.assertEqual(evaluate_http({'manifest_xml':'<!DOCTYPE a [<!ENTITY b "c">]><manifest/>'},35,'default')['verdict'],'unknown')

    def test_partial_cli_and_comparison_cli(self):
        with tempfile.TemporaryDirectory() as t:
            t=Path(t); i=t/'i.json'; r=t/'r.json'
            i.write_text(json.dumps(intent())); r.write_text(json.dumps(report(complete=False)))
            c=subprocess.run([sys.executable,'-m','intentcheck','match','--intent',str(i),'--static-report',str(r),'--case-id','partial','--out',str(t/'run')],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(c.returncode,3,c.stderr)
            self.assertTrue((t/'run/report.md').exists())
            c=subprocess.run([sys.executable,'-m','intentcheck','compare','--before',str(t/'run/result.json'),'--after',str(t/'run/result.json'),'--episode-id','e','--out',str(t/'comparison')],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(c.returncode,3,c.stderr)
            self.assertTrue((t/'comparison/comparison.json').exists())

class ConfigurationTest(unittest.TestCase):
    def test_limits_can_be_overridden_and_recorded(self):
        with tempfile.TemporaryDirectory() as t:
            t=Path(t); config=t/'config.json'; static=t/'static.json'; i=t/'intent.json'
            config.write_text('{"resource_limits":{"tool_timeout_seconds":120}}')
            static.write_text(json.dumps(report())); i.write_text(json.dumps(intent()))
            args=[sys.executable,'-m','intentcheck','match','--intent',str(i),'--static-report',str(static),'--config',str(config),'--case-id','config','--out',str(t/'run')]
            p=subprocess.run(args,cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(p.returncode,3,p.stderr)
            self.assertEqual(load_json(t/'run/run.json')['limits']['tool_timeout_seconds'],120)
            config.write_text('{"resource_limits":{"tool_timeout_seconds":false}}')
            p=subprocess.run(args[:-1]+[str(t/'bad')],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(p.returncode,2,p.stderr)

    def test_normalized_url_identity(self):
        self.assertEqual(normalize_url('https://user:pass@evil.test/a#frag'),normalize_url('https://evil.test:443/a'))
        self.assertNotEqual(normalize_url('https://evil.test:0/a'),normalize_url('https://evil.test/a'))
