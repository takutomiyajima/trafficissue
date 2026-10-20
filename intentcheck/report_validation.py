"""Validate consumed static-report fields before normalization or matching.

Missing optional evidence stays missing; present fields with the wrong type are
input errors, never extraction failures. Unknown legacy metadata is preserved.
"""
from .validation import CheckError

STATUSES = {'success', 'partial', 'failed', 'unsupported', 'not_run'}
COVERAGES = {'complete_in_scope', 'partial', 'unknown'}


def invalid(path, expected):
    raise CheckError('UNSUPPORTED_SCHEMA', f'{path}: expected {expected}')


def typed(value, cls, path):
    if type(value) is not cls:
        invalid(path, cls.__name__)
    return value


def pointer(value):
    return value.replace('~', '~0').replace('/', '~1')


def optional(obj, field, cls, path, nullable=False):
    if field in obj and not (nullable and obj[field] is None):
        typed(obj[field], cls, path+'/'+pointer(field))


def stages(value, path):
    typed(value, dict, path)
    for name, stage in value.items():
        loc = path+'/'+pointer(name)
        typed(stage, dict, loc)
        for field, allowed in (('status', STATUSES), ('coverage', COVERAGES)):
            if field in stage and (not isinstance(stage[field], str) or stage[field] not in allowed):
                invalid(loc+'/'+field, 'one of '+', '.join(sorted(allowed)))
        for field in ('scanned_members', 'excluded_members', 'errors', 'warnings'):
            optional(stage, field, list, loc)


def validate_report(report):
    typed(report, dict, '/')
    for field in ('application', 'stages'):
        if field not in report:
            invalid('/'+field, 'object')
        typed(report[field], dict, '/'+field)
    for field in ('package_name', 'version_name', 'version_code', 'sha256'):
        # Historical aapt reports use strings (or null) for these values.
        optional(report['application'], field, str, '/application', nullable=True)
    if 'analysis_status' in report and report['analysis_status'] not in ('success', 'partial', 'failed', 'unsupported', 'not_run'):
        invalid('/analysis_status', 'analysis status string')
    stages(report['stages'], '/stages')
    for field in ('permissions', 'findings'):
        if field not in report:
            continue
        typed(report[field], list, '/'+field)
        for i, item in enumerate(report[field]):
            loc = f'/{field}/{i}'
            typed(item, dict, loc)
            if field == 'permissions':
                optional(item, 'name', str, loc)
                optional(item, 'locator', str, loc, nullable=True)
            else:
                optional(item, 'signal_type', str, loc)
                if item.get('signal_type') in ('url', 'domain'):
                    if 'value' not in item:
                        invalid(loc+'/value', 'string')
                    typed(item['value'], str, loc+'/value')
                    optional(item, 'evidence', str, loc)
    for field in ('sdk_hints', 'sdk_metadata'):
        if field not in report:
            continue
        typed(report[field], dict, '/'+field)
        for label, value in report[field].items():
            loc = '/'+field+'/'+pointer(label)
            if field == 'sdk_metadata':
                typed(value, dict, loc)
                optional(value, 'id', str, loc)
            else:
                typed(value, list, loc)
                for i, hint in enumerate(value):
                    typed(hint, str, f'{loc}/{i}')
    if 'intentcheck_extraction' not in report:
        return
    ext = typed(report['intentcheck_extraction'], dict, '/intentcheck_extraction')
    base = '/intentcheck_extraction'
    optional(ext, 'version', str, base)
    optional(ext, 'permissions_structural', bool, base)
    if 'stages' in ext:
        stages(ext['stages'], base+'/stages')
    if 'url_occurrences' in ext:
        typed(ext['url_occurrences'], list, base+'/url_occurrences')
        for i, item in enumerate(ext['url_occurrences']):
            loc = f'{base}/url_occurrences/{i}'
            typed(item, dict, loc)
            if 'value' not in item:
                invalid(loc+'/value', 'string')
            typed(item['value'], str, loc+'/value')
            for field in ('pointer', 'method', 'role'):
                optional(item, field, str, loc)
            for field in ('apk_member', 'locator'):
                optional(item, field, str, loc, nullable=True)
    if 'http_configuration' in ext:
        config = typed(ext['http_configuration'], dict, base+'/http_configuration')
        loc = base+'/http_configuration'
        for field in ('manifest_xml', 'nsc_xml', 'resource_resolution'):
            optional(config, field, str, loc)
        if 'resource_variants' in config:
            typed(config['resource_variants'], list, loc+'/resource_variants')
            for i, value in enumerate(config['resource_variants']):
                typed(value, str, f'{loc}/resource_variants/{i}')
    if 'tool_fingerprints' in ext:
        fingerprints = typed(ext['tool_fingerprints'], dict, base+'/tool_fingerprints')
        for name, value in fingerprints.items():
            loc = base+'/tool_fingerprints/'+pointer(name)
            typed(value, dict, loc)
            for field, sha in value.items():
                if not isinstance(sha, str) or len(sha) != 64 or any(c not in '0123456789abcdefABCDEF' for c in sha):
                    invalid(loc+'/'+pointer(field), 'SHA-256 hexadecimal string')
