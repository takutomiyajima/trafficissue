"""Bounded wrapper around the existing analyzer plus structural evidence extraction."""
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from .validation import CheckError, load_json, file_hash
from .http_policy import ANDROID, xml_root

LIMITS = {'apk_bytes': 300*1024**2, 'json_bytes': 100*1024**2,
          'uncompressed_bytes': 2*1024**3, 'members': 100000,
          'member_bytes': 64*1024**2, 'tool_timeout_seconds': 300,
          'address_space_bytes': 4*1024**3}
URL_BYTES = re.compile(rb'https?://[^\s\x00-\x20\x7f-\xff"\'<>]+')


def child_limits():
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (LIMITS['address_space_bytes'], LIMITS['address_space_bytes']))
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMITS['json_bytes'], LIMITS['json_bytes']))


def run_tool(command):
    try:
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            p = subprocess.run(command, stdout=out, stderr=err, timeout=LIMITS['tool_timeout_seconds'],
                               preexec_fn=child_limits)
            out.seek(0); err.seek(0)
            stdout = out.read(LIMITS['json_bytes']+1)
            if len(stdout) > LIMITS['json_bytes']:
                raise CheckError('INPUT_LIMIT', 'tool output limit exceeded', 4)
            return p.returncode, stdout.decode('utf-8', errors='replace'), err.read(8192).decode('utf-8', errors='replace')
    except subprocess.TimeoutExpired as e:
        raise CheckError('TOOL_TIMEOUT', 'extractor timed out', 4) from e


def inspect_apk(apk):
    if Path(apk).stat().st_size > LIMITS['apk_bytes']:
        raise CheckError('INPUT_LIMIT', 'APK exceeds 300 MiB', 4)
    try:
        with zipfile.ZipFile(apk) as z:
            infos = z.infolist()
            if len(infos) > LIMITS['members'] or sum(x.file_size for x in infos) > LIMITS['uncompressed_bytes']:
                raise CheckError('INPUT_LIMIT', 'APK archive exceeds member/expanded-size limit', 4)
            names = [x.filename for x in infos]
            if len(names) != len(set(names)):
                raise CheckError('INVALID_APK', 'duplicate archive members', 2)
            for info in infos:
                path = PurePosixPath(info.filename)
                if path.is_absolute() or '..' in path.parts or '\\' in info.filename or (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise CheckError('INVALID_APK', 'unsafe archive member', 2)
            if 'AndroidManifest.xml' not in names:
                raise CheckError('INVALID_APK', 'missing AndroidManifest.xml')
    except zipfile.BadZipFile as e:
        raise CheckError('INVALID_APK', 'APK is not a valid ZIP') from e


def extract(apk, workdir):
    inspect_apk(apk)
    apk = str(Path(apk).resolve())
    root = Path(__file__).resolve().parent.parent
    report_path = Path(workdir)/'static.json'
    code, _, stderr = run_tool([sys.executable, str(root/'static_analyzer.py'), apk,
                               '--output', str(Path(workdir)/'static.csv'), '--json-output', str(report_path)])
    if code or not report_path.exists():
        raise CheckError('TOOL_FAILED', 'static analyzer failed: '+stderr[-2000:], 4)
    report = load_json(report_path)
    ext = {'version': '1.0', 'stages': {}, 'url_occurrences': [], 'http_configuration': {}}
    report['intentcheck_extraction'] = ext
    analyzer = shutil.which('apkanalyzer')
    ext['tool_fingerprints'] = {}
    for name in ('aapt', 'aapt2', 'apkanalyzer'):
        executable = shutil.which(name)
        if executable:
            ext['tool_fingerprints'][name] = {'executable_sha256': file_hash(executable)}
    ext['tool_fingerprints']['static_analyzer.py'] = {'source_sha256': file_hash(root/'static_analyzer.py')}
    manifest = ''
    if analyzer:
        code, manifest, _ = run_tool([analyzer, 'manifest', 'print', apk])
        if code:
            manifest = ''
    # Plain XML in a development fixture is also valid structural evidence.
    with zipfile.ZipFile(apk) as z:
        if not manifest and z.getinfo('AndroidManifest.xml').file_size <= LIMITS['member_bytes']:
            raw = z.read('AndroidManifest.xml')
            if raw.lstrip().startswith(b'<'):
                manifest = raw.decode('utf-8')
        try:
            tree = xml_root(manifest)
            if tree.tag != 'manifest' or not tree.get('package'):
                raise ValueError('invalid manifest root/package')
            report['application']['package_name'] = tree.get('package')
            for key, attr in [('version_name', 'versionName'), ('version_code', 'versionCode')]:
                if tree.get(ANDROID+attr):
                    report['application'][key] = tree.get(ANDROID+attr)
            report['permissions'] = []
            for i, node in enumerate(tree):
                if node.tag in ('uses-permission', 'uses-permission-sdk-23', 'uses-permission-sdk-m'):
                    name = node.get(ANDROID+'name')
                    if not name or name.startswith('@'):
                        raise ValueError('unresolved permission name')
                    report['permissions'].append({'name': name, 'element': node.tag,
                                                  'maxSdkVersion': node.get(ANDROID+'maxSdkVersion'),
                                                  'locator': f'/manifest/{node.tag}[{i}]'})
            ext['permissions_structural'] = True
            ext['stages']['permissions'] = {'status': 'success', 'coverage': 'complete_in_scope',
                                            'scope': 'uses-permission and uses-permission-sdk-23/sdk-m declarations'}
            config = ext['http_configuration']
            config['manifest_xml'] = manifest
            app = tree.find('application')
            ref = app.get(ANDROID+'networkSecurityConfig') if app is not None else None
            if ref:
                match = re.fullmatch(r'@xml/([A-Za-z0-9_]+)', ref)
                config['resource_resolution'] = 'unresolved'
                if match:
                    base = 'res/xml/'+match[1]+'.xml'
                    config['resource_variants'] = [n for n in z.namelist() if re.fullmatch(r'res/xml-[^/]+/'+re.escape(match[1])+r'\.xml', n)]
                    if base in z.namelist() and z.getinfo(base).file_size <= LIMITS['member_bytes']:
                        raw = z.read(base)
                        if raw.lstrip().startswith(b'<'):
                            config['nsc_xml'] = raw.decode('utf-8')
                            config['resource_resolution'] = 'resolved_default'
                        elif analyzer:
                            code, xml, _ = run_tool([analyzer, 'resources', 'xml', '--file', base, apk])
                            if code == 0:
                                config['nsc_xml'] = xml
                                config['resource_resolution'] = 'resolved_default'
        except (ValueError, ET.ParseError, UnicodeError):
            ext['permissions_structural'] = False
            ext['stages']['permissions'] = {'status': 'partial', 'coverage': 'partial', 'scope': 'Manifest decode failed'}
        partial = []
        scanned = []
        excluded = []
        for info in z.infolist():
            name = info.filename
            if info.is_dir():
                continue
            if not (name.endswith(('.dex', '.xml', '.json', '.txt', '.html', '.js', '.properties')) or name.startswith('assets/')):
                excluded.append(name)
                continue
            if info.file_size > LIMITS['member_bytes']:
                partial.append(name)
                continue
            try:
                raw = z.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                partial.append(name)
                continue
            scanned.append(name)
            namespaces = {}
            if name.endswith('.xml') and raw.lstrip().startswith(b'<'):
                try:
                    import io
                    xml_root(raw.decode('utf-8'))
                    for _, pair in ET.iterparse(io.BytesIO(raw), events=('start-ns',)):
                        uri = pair[1]
                        namespaces[uri] = namespaces.get(uri, 0)+1
                except (ET.ParseError, ValueError, UnicodeError):
                    namespaces = {}
            for m in URL_BYTES.finditer(raw):
                value = m.group().decode('ascii')
                item = {'value': value, 'apk_member': name, 'locator': f'byte:{m.start()}', 'method': 'ascii_member_string'}
                # Only remove the exact occurrence inside an xmlns attribute, never all identical strings.
                prefix = raw[max(0, m.start()-200):m.start()]
                if value in namespaces and re.search(rb'xmlns(?::[\w.-]+)?\s*=\s*["\']$', prefix):
                    item.update(role='xml_namespace', method='xml_namespace_declaration')
                ext['url_occurrences'].append(item)
        ext['stages']['endpoints'] = {'status': 'partial' if partial else 'success',
                                      'coverage': 'partial' if partial else 'complete_in_scope',
                                      'scope': 'ASCII HTTP(S) candidates in DEX/XML/text/assets; no native/UTF-16/generated URLs',
                                      'scanned_members': scanned, 'excluded_members': excluded, 'errors': partial}
    return report
