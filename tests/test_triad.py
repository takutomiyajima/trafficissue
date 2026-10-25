import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib
from intentcheck.validation import CheckError
from intentcheck.triad_input import validate_case
from intentcheck.triad_match import match
from intentcheck.triad import imported_sdk, report_text
from intentcheck.sdk import REGISTRY, REGISTRY_HASH, dex_classes, scan_sdk

ROOT=Path(__file__).resolve().parent.parent
EXAMPLE=ROOT/'examples/triad'


def inputs():
    case=json.loads((EXAMPLE/'case.json').read_text())
    report=json.loads((EXAMPLE/'static.json').read_text())
    return case,report,imported_sdk(report)


def claim(id,domain,predicate,value,**kw):
    c=copy.deepcopy(inputs()[0]['claims'][0])
    c.update(claim_id=id,domain=domain,predicate=predicate,value=value,**kw)
    return c


def requirement(domain, value):
    return {'requirement_id':'r','source':{'document_id':'request','start_line':1,'end_line':1},
            'domain':domain,'predicate':'denylist' if domain=='sdk' else 'allowlist','value':value,
            'scope':'exact','explicit':True,'confirmation':inputs()[0]['claims'][0]['confirmation']}


def synthetic_dex(classes, extra_strings=()):
    strings=list(classes)+list(extra_strings)
    so=112; to=so+4*len(strings); co=to+4*len(classes); dataoff=co+32*len(classes)
    data=bytearray(dataoff)
    data[:8]=b'dex\n035\0'
    def put(o,v): struct.pack_into('<I',data,o,v)
    put(36,112);put(40,0x12345678)
    for o,v in [(56,len(strings)),(60,so),(64,len(classes)),(68,to),(96,len(classes)),(100,co)]: put(o,v)
    for i,s in enumerate(strings):
        put(so+4*i,len(data))
        n=len(s); prefix=[]
        while n>=128: prefix.append((n&127)|128);n>>=7
        prefix.append(n)
        data.extend(bytes(prefix)+s.encode()+b'\0')
    for i in range(len(classes)): put(to+4*i,i);put(co+32*i,i)
    put(32,len(data));data[12:32]=hashlib.sha1(data[32:]).digest();put(8,zlib.adler32(data[12:])&0xffffffff)
    return bytes(data)


class TriadAcceptance(unittest.TestCase):
    def test_requirement_unspecified_claim_contradicted_separate(self):
        c,r,s=inputs(); result=match(c,r,s)
        self.assertTrue(any(f['axis']=='requirement' and f['verdict']=='unspecified' for f in result['findings']))
        self.assertEqual(next(f['verdict'] for f in result['findings'] if f['claim_ids']==['no-location'] and f['axis']=='claim'),'contradicted')
        self.assertTrue(any(f['verdict']=='out_of_scope' and f['claim_ids']==['no-traffic'] for f in result['findings']))
        self.assertTrue(any(f['verdict']=='not_asserted' for f in result['findings']))

    def test_complete_absence_and_partial_extraction(self):
        c,r,s=inputs();c['claims']=[claim('present','permissions','present','android.permission.CAMERA')]
        result=match(c,r,s)
        self.assertTrue(any(f['axis']=='claim' and f['verdict']=='contradicted' and f['evidence_ids'] for f in result['findings']))
        del r['permissions']
        result=match(c,r,s)
        self.assertEqual(next(f['verdict'] for f in result['findings'] if f['axis']=='claim'),'insufficient_evidence')
        r=inputs()[1]; r['intentcheck_extraction']['stages']['permissions']['coverage']='partial'
        c['claims']=[claim('negative','permissions','absent','android.permission.ACCESS_FINE_LOCATION')]
        c['requirements']=[requirement('permissions',[])]
        result=match(c,r,s)
        self.assertTrue(result['has_unknowns'])
        self.assertTrue(any(f['verdict']=='mismatch' for f in result['findings']))
        self.assertTrue(any(f['verdict']=='contradicted' for f in result['findings']))
        self.assertTrue(any(f['verdict']=='unknown' for f in result['findings']))

    def test_url_boundary_userinfo_dedup_and_no_causal_links(self):
        c,r,s=inputs();c['requirements']=[requirement('endpoints',[{'host':'api.example.com','include_subdomains':False}])]
        r['findings']=[{'signal_type':'url','value':u} for u in ['https://api.example.com.evil.test/a','https://api.example.com@evil.test/a','https://api.example.com@evil.test/a']]
        result=match(c,r,s)
        self.assertEqual(result['facts']['url_candidates'][1]['host'],'evil.test')
        self.assertEqual(len(result['facts']['url_candidates'][1]['evidence_ids']),2)
        self.assertEqual(sum(f['verdict']=='needs_review' for f in result['findings']),2)
        self.assertFalse(any(f['verdict']=='mismatch' for f in result['findings']))
        self.assertNotIn('data_flow',result)

    def test_omission_unavailable_partial_and_negative_mention(self):
        c,r,s=inputs();c['claims']=[]
        self.assertTrue(any(f['verdict']=='omission_candidate' for f in match(c,r,s)['findings']))
        c['documents'][1]['review']['status']='partial'
        self.assertFalse(any(f['verdict']=='omission_candidate' for f in match(c,r,s)['findings']))
        c['documents']=c['documents'][:1]
        res=match(c,r,s)
        self.assertTrue(any(f['verdict']=='explanation_unavailable' for f in res['findings']))
        c,r,s=inputs()
        self.assertTrue(any(f['axis']=='coverage' and f['verdict']=='covered' and f['domain']=='permissions' for f in match(c,r,s)['findings']))
        c['claims']=[claim('general','permissions','present','android.permission.INTERNET',scope='general')]
        self.assertTrue(any(f['verdict']=='ambiguous' for f in match(c,r,s)['findings']))

    def test_sdk_structural_signature_hint_non_detection_and_corruption(self):
        rule=REGISTRY['rules'][0]
        with tempfile.TemporaryDirectory() as t:
            apk=Path(t)/'sdk.apk'
            with zipfile.ZipFile(apk,'w') as z:z.writestr('classes.dex',synthetic_dex(rule['required_classes']))
            sdk=scan_sdk(apk,1024**2)
            self.assertEqual(sdk['entries'][0]['strength'],'sdk_signature')
            c,r,_=inputs(); c['claims']=[claim('maps','sdk','absent','google_maps')]
            result=match(c,r,sdk)
            self.assertTrue(any(f['axis']=='claim' and f['verdict']=='contradicted' for f in result['findings']))
            self.assertTrue(any(f['axis']=='coverage' and f['verdict']=='covered' for f in result['findings']))
            c['claims']=[]
            self.assertTrue(any(f['domain']=='sdk' and f['verdict']=='omission_candidate' for f in match(c,r,sdk)['findings']))
            with zipfile.ZipFile(apk,'w') as z:z.writestr('classes.dex',synthetic_dex([],rule['required_classes'][:1]))
            hint=scan_sdk(apk,1024**2)
            self.assertEqual(hint['entries'][0]['strength'],'embedded_string')
            c['claims']=[claim('maps','sdk','absent','google_maps')]
            self.assertEqual(next(f['verdict'] for f in match(c,r,hint)['findings'] if f['axis']=='claim'),'insufficient_evidence')
            no_sdk=imported_sdk(r)
            self.assertEqual(next(f['verdict'] for f in match(c,r,no_sdk)['findings'] if f['axis']=='claim'),'insufficient_evidence')
            broken=bytearray(synthetic_dex(rule['required_classes']));broken[-2]^=1
            with self.assertRaises(ValueError):dex_classes(bytes(broken))
            with zipfile.ZipFile(apk,'w') as z:z.writestr('classes.dex',broken)
            self.assertEqual(scan_sdk(apk,1024**2)['stage']['coverage'],'partial')

    def test_validation_references_predicates_original_hash_and_speech(self):
        c,_,_=inputs();validate_case(c,EXAMPLE)
        for change in ('ref','predicate','hash','artifact','unconfirmed','evidence','duplicate'):
            bad=copy.deepcopy(c)
            if change=='ref':bad['claims'][0]['source']['start_line']=100
            if change=='predicate':bad['claims'][0]['predicate']='sent_location'
            if change=='hash':bad['documents'][0]['sha256']='b'*64
            if change=='artifact':bad['documents'][0]['artifact_id']='other'
            if change=='unconfirmed':bad['claims'][0]['confirmation']={}
            if change=='evidence':bad['claims'][0]['evidence_ids']=['fake']
            if change=='duplicate':bad['claims'].append(copy.deepcopy(bad['claims'][0]))
            with self.subTest(change=change),self.assertRaises(CheckError):validate_case(bad,EXAMPLE)

    def test_cli_reproducibility_outputs_review_and_oracle_independence(self):
        with tempfile.TemporaryDirectory() as t:
            t=Path(t)
            def run(out):
                return subprocess.run([sys.executable,'-m','intentcheck','triangulate','--case',str(EXAMPLE/'case.json'),'--static-report',str(EXAMPLE/'static.json'),'--out',str(out)],cwd=ROOT,capture_output=True,text=True)
            for name in ('a','b'):
                (t/'oracle.json').write_text(name)
                p=run(t/name);self.assertEqual(p.returncode,3,p.stderr)
            a=json.loads((t/'a/result.json').read_text());b=json.loads((t/'b/result.json').read_text())
            self.assertEqual(a,b)
            self.assertFalse(a['evaluation_eligible'])
            import csv
            with (t/'a/findings.csv').open() as f: rows=list(csv.DictReader(f))
            self.assertEqual([f['finding_id'] for f in a['findings']],[f['finding_id'] for f in rows])
            for name in ('report.md','baseline.md'):
                report=(t/'a'/name).read_text()
                for f in a['findings']:self.assertIn(f['finding_id'],report)
                for e in a['facts']['evidence']:self.assertIn(e['evidence_id'],report)
            refs={e['evidence_id'] for e in a['facts']['evidence']}
            self.assertTrue(all(set(f['evidence_ids'])<=refs for f in a['findings']))
            self.assertFalse((t/'a/INCOMPLETE').exists())
            raw=t/'a/raw_inputs'
            self.assertEqual((raw/'original_static_analysis.json').read_bytes(),(EXAMPLE/'static.json').read_bytes())
            rev=t/'review.json';rev.write_text(json.dumps([{'run_id':a['run_id'],'finding_id':a['findings'][0]['finding_id'],'reviewer':'human','note':'manual'}]))
            p=subprocess.run([sys.executable,'-m','intentcheck','join-reviews','--result',str(t/'a/result.json'),'--reviews',str(rev),'--out',str(t/'reviews')],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual(json.loads((t/'a/result.json').read_text()),a)

class TriadAdditionalBoundaries(unittest.TestCase):
    def test_supported_claims_exact_url_and_possibility(self):
        c,r,s=inputs()
        c['claims']=[claim('p','permissions','present','android.permission.ACCESS_FINE_LOCATION'),
                     claim('u','endpoints','present','https://maps.example.com/path'),
                     claim('maybe','permissions','absent','android.permission.ACCESS_FINE_LOCATION',certainty='possible')]
        result=match(c,r,s)
        verdicts={f['claim_ids'][0]:f['verdict'] for f in result['findings'] if f['axis']=='claim'}
        self.assertEqual(verdicts,{'p':'supported_in_scope','u':'supported_in_scope','maybe':'insufficient_evidence'})
        c['requirements']=[requirement('permissions',['android.permission.ACCESS_FINE_LOCATION'])]
        self.assertTrue(any(f['axis']=='requirement' and f['verdict']=='conform_in_scope' and f['evidence_ids'] for f in match(c,r,s)['findings']))

    def test_sdk_import_requires_all_signature_classes(self):
        c,r,s=inputs();s=copy.deepcopy(s)
        s['entries']=[{'sdk_id':'google_maps','name':'Maps','category':'location','strength':'sdk_signature','classes':{},'hint_members':[]}]
        r['triad_sdk']=s
        with self.assertRaises(CheckError):imported_sdk(r)

    def test_apk_identity_and_generation_entrypoint(self):
        with tempfile.TemporaryDirectory() as t:
            t=Path(t)
            for filename in ('request.txt','explanation.txt'):(t/filename).write_bytes((EXAMPLE/filename).read_bytes())
            c,r,_=inputs()
            apk=t/'fixture.apk'
            with zipfile.ZipFile(apk,'w') as z:
                z.writestr('AndroidManifest.xml','<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.app"><uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/><application/></manifest>')
                z.writestr('classes.dex',synthetic_dex(REGISTRY['rules'][0]['required_classes']))
            c['artifact']['apk_sha256']=hashlib.sha256(apk.read_bytes()).hexdigest()
            (t/'case.json').write_text(json.dumps(c))
            cmd=[sys.executable,'-m','intentcheck','triangulate','--case',str(t/'case.json'),'--apk',str(apk),'--out',str(t/'out')]
            p=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True)
            self.assertIn(p.returncode,(0,3),p.stderr)
            result=json.loads((t/'out/result.json').read_text())
            self.assertTrue(result['evaluation_eligible'])
            self.assertTrue(any(x['strength']=='sdk_signature' for x in result['configurations']))
            (t/'wrong.json').write_text(json.dumps(r))
            p=subprocess.run(cmd[:-1]+[str(t/'bad'),'--static-report',str(t/'wrong.json')],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(p.returncode,2,p.stderr)
            self.assertEqual(json.loads(p.stderr)['code'],'ARTIFACT_MISMATCH')

class MultiDexBoundary(unittest.TestCase):
    def test_classes_ten_and_cross_member_signature(self):
        classes=REGISTRY['rules'][0]['required_classes']
        with tempfile.TemporaryDirectory() as t:
            apk=Path(t)/'multi.apk'
            with zipfile.ZipFile(apk,'w') as z:
                z.writestr('classes.dex',synthetic_dex(classes[:1]))
                z.writestr('classes10.dex',synthetic_dex(classes[1:]))
            sdk=scan_sdk(apk,1024**2)
            self.assertEqual(sdk['entries'][0]['strength'],'sdk_signature')
            self.assertEqual(len(sdk['stage']['scanned_members']),2)
            c,r,_=inputs();result=match(c,r,sdk)
            self.assertTrue(all(e['source_report_pointer'].startswith('/triad_sdk/') for e in result['facts']['evidence'] if e['kind']=='sdk_signature'))

class PartialToolFailure(unittest.TestCase):
    def test_tool_timeout_retains_independent_sdk_evidence(self):
        from unittest.mock import patch
        from intentcheck.__main__ import parser
        from intentcheck.triad import run
        with tempfile.TemporaryDirectory() as t:
            t=Path(t)
            for f in ('request.txt','explanation.txt'):(t/f).write_bytes((EXAMPLE/f).read_bytes())
            apk=t/'fixture.apk'
            with zipfile.ZipFile(apk,'w') as z:
                z.writestr('AndroidManifest.xml',b'opaque')
                z.writestr('classes.dex',synthetic_dex(REGISTRY['rules'][0]['required_classes']))
            c,_,_=inputs();c['artifact']['apk_sha256']=hashlib.sha256(apk.read_bytes()).hexdigest()
            c['claims']=[claim('no-maps','sdk','absent','google_maps')]
            (t/'case.json').write_text(json.dumps(c))
            args=parser().parse_args(['triangulate','--case',str(t/'case.json'),'--apk',str(apk),'--out',str(t/'out')])
            with patch('intentcheck.triad.extract',side_effect=CheckError('TOOL_TIMEOUT','timeout',4)):
                self.assertEqual(run(args),3)
            result=json.loads((t/'out/result.json').read_text())
            self.assertTrue(any(f['verdict']=='contradicted' for f in result['findings']))
            self.assertTrue(result['has_unknowns'])
            self.assertEqual(result['stages'][0]['status'],'failed')
