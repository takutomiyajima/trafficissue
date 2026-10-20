import copy
import datetime as dt
import hashlib
import ipaddress
import json
import re
from pathlib import Path

JSON_LIMIT = 100 * 1024 * 1024
REGISTRY_VERSION = 'trafficissue-hints-1'
SDK_IDS = {'firebase_analytics', 'google_ads', 'google_maps', 'facebook', 'adjust', 'appsflyer'}


class CheckError(Exception):
    def __init__(self, code, message, exit_code=2):
        self.code, self.exit_code = code, exit_code
        super().__init__(message)


def fail(path, message):
    raise CheckError('INVALID_INTENT', f'{path}: {message}')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def load_json(path):
    if Path(path).stat().st_size > JSON_LIMIT:
        raise CheckError('INPUT_LIMIT', f'{path}: JSON exceeds {JSON_LIMIT} bytes')
    def pairs(items):
        obj = {}
        for k, v in items:
            if k in obj:
                raise CheckError('INVALID_JSON', f'Duplicate JSON key: {k}')
            obj[k] = v
        return obj
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda x: fail('/', f'Invalid JSON constant {x}'))
    except (ValueError, UnicodeError) as e:
        raise CheckError('INVALID_JSON', str(e)) from e


def object_keys(obj, required, optional, path):
    if not isinstance(obj, dict):
        fail(path, 'object required')
    if set(obj) - set(required) - set(optional):
        fail(path, f'unknown keys: {sorted(set(obj)-set(required)-set(optional))}')
    if set(required) - set(obj):
        fail(path, f'missing keys: {sorted(set(required)-set(obj))}')


def host(value):
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError('host must be a nonempty DNS name or IP')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    value = value[:-1] if value.endswith('.') else value
    value = value.encode('idna').decode('ascii').lower()
    if len(value) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in value.split('.')):
        raise ValueError('invalid DNS host (scheme, port, path and wildcard are forbidden)')
    return value


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_intent(source):
    obj = copy.deepcopy(source)
    warnings = []
    required = ['intent_schema_version', 'intent_id', 'intent_version', 'recorded_at', 'source_request',
                'permissions', 'endpoints', 'cleartext_configuration', 'sdk_inclusion']
    object_keys(obj, required, [], '/')
    for key in required[:5]:
        if not isinstance(obj[key], str) or not obj[key].strip():
            fail('/'+key, 'nonempty string required')
    if obj['intent_schema_version'] != '1.0':
        fail('/intent_schema_version', 'only 1.0 is supported; migrate older files explicitly')
    try:
        timestamp = dt.datetime.fromisoformat(obj['recorded_at'])
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError()
    except ValueError:
        fail('/recorded_at', 'ISO 8601 timestamp with timezone required')
    fields = {'permissions': ('allowlist', ['allowed']), 'endpoints': ('allowlist', ['allowed_hosts']),
              'cleartext_configuration': ('deny', ['runtime_api_levels', 'resource_profile']),
              'sdk_inclusion': ('denylist', ['denied_sdk_ids', 'registry_version'])}
    for key, (mode, keys) in fields.items():
        p = obj[key]
        object_keys(p, ['mode'], keys, '/'+key)
        if p['mode'] == 'unspecified':
            object_keys(p, ['mode'], [], '/'+key)
            continue
        if p['mode'] != mode:
            fail('/'+key+'/mode', f'expected {mode} or unspecified')
        object_keys(p, ['mode']+keys, [], '/'+key)
        arrkey = keys[0]
        values = p[arrkey]
        if not isinstance(values, list):
            fail('/'+key+'/'+arrkey, 'array required')
        clean = []
        for i, value in enumerate(values):
            loc = f'/{key}/{arrkey}/{i}'
            if key == 'endpoints':
                object_keys(value, ['host', 'include_subdomains'], [], loc)
                if type(value['include_subdomains']) is not bool:
                    fail(loc, 'include_subdomains must be boolean')
                try:
                    value['host'] = host(value['host'])
                except (ValueError, UnicodeError) as e:
                    fail(loc+'/host', str(e))
                if is_ip(value['host']) and value['include_subdomains']:
                    fail(loc, 'IP cannot include subdomains')
            elif key == 'cleartext_configuration':
                if type(value) is not int or value < 1:
                    fail(loc, 'positive integer API level required')
                if value in clean:
                    fail(loc, 'duplicate API level')
            else:
                if not isinstance(value, str) or not value:
                    fail(loc, 'nonempty string required')
                if key == 'permissions' and not re.fullmatch(r'[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+', value, re.ASCII):
                    fail(loc, 'fully qualified permission name required')
                if key == 'sdk_inclusion' and value not in SDK_IDS:
                    fail(loc, 'SDK ID not registered in '+REGISTRY_VERSION)
            if value in clean:
                warnings.append({'code': 'DUPLICATE_VALUE', 'path': loc})
            else:
                clean.append(value)
        p[arrkey] = clean
        if key == 'cleartext_configuration':
            if not clean:
                fail('/'+key+'/runtime_api_levels', 'at least one runtime API required')
            if not isinstance(p['resource_profile'], str) or not p['resource_profile']:
                fail('/'+key+'/resource_profile', 'nonempty string required')
        if key == 'sdk_inclusion' and p['registry_version'] != REGISTRY_VERSION:
            fail('/'+key+'/registry_version', 'expected '+REGISTRY_VERSION)
    return obj, warnings
