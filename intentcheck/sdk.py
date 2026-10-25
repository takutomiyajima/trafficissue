"""Fixed, narrow SDK API-subset signatures over DEX class definitions.

Matching proves named class definitions are present, not their vendor provenance,
execution or whole SDK identity. R8/obfuscation and dynamic code are unsupported.
"""
import hashlib
import json
import re
import struct
import zipfile
import zlib
from .validation import digest

REGISTRY = {
    'version': 'dex-api-subsets-1',
    'scope': 'Unobfuscated DEX 035-040 class definitions; named API subsets only',
    'obfuscation': 'unsupported; absence never establishes SDK absence',
    'rules': [
        {'sdk_id': 'google_maps', 'category': 'location', 'name': 'Google Maps API subset',
         'required_classes': ['Lcom/google/android/gms/maps/MapView;', 'Lcom/google/android/gms/maps/MapsInitializer;']},
        {'sdk_id': 'firebase_analytics', 'category': 'analytics', 'name': 'Firebase Analytics API subset',
         'required_classes': ['Lcom/google/firebase/analytics/FirebaseAnalytics;', 'Lcom/google/firebase/analytics/FirebaseAnalytics$Event;']}
    ],
    'limitations': ['Class names can be copied/spoofed; no vendor authenticity proof',
                    'General SDK purposes do not establish this app usage',
                    'Acceptance fixtures are artificial, not a real-world detection benchmark']}
REGISTRY_HASH = digest(json.dumps(REGISTRY, sort_keys=True).encode())


def dex_classes(data):
    if len(data) < 112 or data[:8] not in [f'dex\n{n:03d}\0'.encode() for n in range(35, 41)]:
        raise ValueError('unsupported DEX header')
    def u32(offset):
        return struct.unpack_from('<I', data, offset)[0]
    if u32(32) != len(data) or u32(36) != 112 or u32(40) != 0x12345678:
        raise ValueError('invalid DEX size/header/endian')
    if hashlib.sha1(data[32:]).digest() != data[12:32] or zlib.adler32(data[12:]) & 0xffffffff != u32(8):
        raise ValueError('DEX integrity check failed')
    def table(sizeoff, off, width):
        count, start = u32(sizeoff), u32(off)
        if count and (start < 112 or start+count*width > len(data)):
            raise ValueError('DEX table out of bounds')
        return count, start
    strings, so = table(56, 60, 4)
    types, to = table(64, 68, 4)
    classes, co = table(96, 100, 32)
    found = {}
    for i in range(classes):
        classidx = u32(co+32*i)
        if classidx >= types:
            raise ValueError('invalid type index')
        stringidx = u32(to+classidx*4)
        if stringidx >= strings:
            raise ValueError('invalid string index')
        start = u32(so+stringidx*4)
        if start < 112 or start >= len(data):
            raise ValueError('invalid string offset')
        # Skip bounded ULEB128 UTF-16 length. Supported signatures are ASCII.
        for _ in range(5):
            if start >= len(data):
                raise ValueError('truncated ULEB128')
            byte = data[start]; start += 1
            if byte < 128:
                break
        else:
            raise ValueError('invalid ULEB128')
        end = data.find(b'\0', start, min(start+65536, len(data)))
        if end < 0:
            raise ValueError('unterminated descriptor')
        value = data[start:end].decode('ascii', errors='replace')
        if not re.fullmatch(r'L[^;\s]+;', value):
            raise ValueError('invalid class descriptor')
        found[value] = f'class_defs[{i}]@{co+32*i}'
    return found


def scan_sdk(apk, member_limit):
    definitions, hints, scanned, errors = {}, {}, [], []
    with zipfile.ZipFile(apk) as archive:
        for item in archive.infolist():
            if not re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex', item.filename):
                continue
            if item.file_size > member_limit:
                errors.append({'member': item.filename, 'reason': 'member size limit'})
                continue
            try:
                data = archive.read(item)
                classes = dex_classes(data)
                scanned.append(item.filename)
                for name, locator in classes.items():
                    definitions.setdefault(name, []).append({'apk_member': item.filename, 'locator': locator})
            except (ValueError, OSError, zipfile.BadZipFile, RuntimeError) as e:
                errors.append({'member': item.filename, 'reason': str(e)})
                continue
            for rule in REGISTRY['rules']:
                if any(c.encode() in data for c in rule['required_classes']):
                    hints.setdefault(rule['sdk_id'], []).append(item.filename)
    entries = []
    for rule in REGISTRY['rules']:
        matched = [c for c in rule['required_classes'] if c in definitions]
        if matched or rule['sdk_id'] in hints:
            entries.append({'sdk_id': rule['sdk_id'], 'name': rule['name'], 'category': rule['category'],
                            'strength': 'sdk_signature' if len(matched)==len(rule['required_classes']) else 'embedded_string',
                            'classes': {c: definitions[c] for c in matched}, 'hint_members': hints.get(rule['sdk_id'], [])})
    return {'registry': REGISTRY, 'registry_hash': REGISTRY_HASH, 'entries': entries,
            'stage': {'status': 'partial' if errors else 'success' if scanned else 'not_run',
                      'coverage': 'partial' if errors else 'complete_in_scope' if scanned else 'unknown',
                      'scope': REGISTRY['scope'], 'scanned_members': scanned, 'errors': errors,
                      'excluded': ['Obfuscated/native/dynamically loaded code', 'SDKs not in registry']}}
