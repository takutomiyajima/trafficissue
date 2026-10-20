"""HTTP-01, Android documented platform configuration, default resources only.

Sources: Android Developers contracts and AOSP android-15.0.0_r1 sources.
Developer documentation was inaccessible (HTTP 403) in this environment; AOSP was inspected.
No conclusions about actual network traffic or native clients.
"""
import xml.etree.ElementTree as ET
from .validation import host

ANDROID = '{http://schemas.android.com/apk/res/android}'
SUPPORT_MATRIX = {'rule_version': '1.0', 'runtime_api_levels': list(range(23, 36)),
                  'target_sdk_range': [1, 35], 'resource_profile': 'default',
                  'sources': ['https://developer.android.com/privacy-and-security/security-config',
                              'https://developer.android.com/guide/topics/manifest/application-element',
                              'https://github.com/aosp-mirror/platform_frameworks_base/blob/android-15.0.0_r1/core/java/android/security/net/config/NetworkSecurityConfig.java',
                              'https://github.com/aosp-mirror/platform_frameworks_base/blob/android-15.0.0_r1/core/java/android/security/net/config/XmlConfigSource.java'],
                  'limitations': ['Android platform configuration only; clients may ignore platform settings',
                                  'Ordinary installed apps only; instant apps are outside scope',
                                  'Resource qualifiers, unresolved references and API >35 are unsupported']}


def xml_root(text):
    if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
        raise ValueError('DTD/entities are unsupported')
    return ET.fromstring(text)


def boolean(value):
    if value not in ('true', 'false'):
        raise ValueError('unresolved or unsupported boolean')
    return value == 'true'


def evaluate_http(config, api, profile):
    """Return effective allowed ranges; preserve unknown instead of guessing."""
    try:
        if profile != 'default' or type(api) is not int or api not in SUPPORT_MATRIX['runtime_api_levels']:
            raise ValueError('UNSUPPORTED_PLATFORM: API/profile outside support matrix')
        root = xml_root(config['manifest_xml'])
        target_nodes = root.findall('uses-sdk')
        if len(target_nodes) > 1:
            raise ValueError('multiple uses-sdk elements')
        target_node = target_nodes[0] if target_nodes else None
        target = int(target_node.get(ANDROID+'targetSdkVersion', target_node.get(ANDROID+'minSdkVersion', '1'))) if target_node is not None else 1
        if not 1 <= target <= 35:
            raise ValueError('UNSUPPORTED_PLATFORM: target SDK outside support matrix')
        apps = root.findall('application')
        if len(apps) != 1:
            raise ValueError('exactly one application is required')
        app = apps[0]
        manifest_value = app.get(ANDROID+'usesCleartextTraffic')
        # Defaults: API <=27 allows; API >=28 disallows when target >=28.
        default = not (api >= 28 and target >= 28)
        nsc = app.get(ANDROID+'networkSecurityConfig')
        ranges = []
        if api < 24 or not nsc:
            allowed = boolean(manifest_value) if manifest_value is not None else default
            ranges.append({'domain': '*', 'include_subdomains': True, 'allowed': allowed})
        else:
            if config.get('resource_variants') or config.get('resource_resolution') != 'resolved_default':
                raise ValueError('UNRESOLVED_RESOURCE: default NSC selection not established')
            tree = xml_root(config['nsc_xml'])
            if tree.tag != 'network-security-config' or tree.attrib:
                raise ValueError('unsupported NSC root')
            bases = tree.findall('base-config')
            if len(bases) > 1:
                raise ValueError('multiple base-config elements')
            def check_attrs(node, permitted):
                if set(node.attrib) - set(permitted):
                    raise ValueError('unsupported NSC attributes')
            def certs(node):
                # Trust anchors do not alter cleartext policy, but reject unknown constructs.
                check_attrs(node, [])
                for child in node:
                    if child.tag != 'certificates':
                        raise ValueError('unsupported trust-anchor element')
                    check_attrs(child, ['src', 'overridePins'])
            base = default
            if bases:
                b = bases[0]
                check_attrs(b, ['cleartextTrafficPermitted'])
                base = boolean(b.attrib['cleartextTrafficPermitted']) if 'cleartextTrafficPermitted' in b.attrib else default
                for child in b:
                    if child.tag != 'trust-anchors':
                        raise ValueError('unsupported base-config element')
                    certs(child)
            ranges.append({'domain': '*', 'include_subdomains': True, 'allowed': base})
            seen = set()
            def domain_config(node, inherited):
                check_attrs(node, ['cleartextTrafficPermitted'])
                allowed = boolean(node.attrib['cleartextTrafficPermitted']) if 'cleartextTrafficPermitted' in node.attrib else inherited
                domains = node.findall('domain')
                if not domains:
                    raise ValueError('domain-config without domains')
                for domain in domains:
                    check_attrs(domain, ['includeSubdomains'])
                    name = host((domain.text or '').strip())
                    if name in seen:
                        raise ValueError('ambiguous duplicate domain')
                    seen.add(name)
                    ranges.append({'domain': name, 'include_subdomains': boolean(domain.get('includeSubdomains', 'false')), 'allowed': allowed})
                for child in node:
                    if child.tag == 'domain-config':
                        domain_config(child, allowed)
                    elif child.tag == 'trust-anchors':
                        certs(child)
                    elif child.tag == 'pin-set':
                        check_attrs(child, ['expiration'])
                        for pin in child:
                            if pin.tag != 'pin':
                                raise ValueError('unsupported pin-set element')
                            check_attrs(pin, ['digest'])
                    elif child.tag != 'domain':
                        raise ValueError('unsupported domain-config element')
            for node in tree:
                if node.tag == 'domain-config':
                    domain_config(node, base)
                elif node.tag == 'debug-overrides':
                    check_attrs(node, [])
                    for child in node:
                        if child.tag != 'trust-anchors':
                            raise ValueError('unsupported debug-overrides element')
                        certs(child)
                elif node.tag != 'base-config':
                    raise ValueError('unsupported NSC element')
        return {'runtime_api': api, 'status': 'success', 'coverage': 'complete_in_scope',
                'target_sdk': target, 'ranges': ranges,
                'verdict': 'mismatch' if any(x['allowed'] for x in ranges) else 'conform_in_scope'}
    except (ValueError, KeyError, TypeError, ET.ParseError) as e:
        return {'runtime_api': api, 'status': 'unsupported', 'coverage': 'unknown',
                'ranges': [], 'verdict': 'unknown', 'reason': str(e)}
