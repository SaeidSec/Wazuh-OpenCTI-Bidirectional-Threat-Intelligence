#!/usr/bin/env python3
"""
Wazuh <-> OpenCTI integration  (AegisryxLabs master edition)
Bidirectional, zero third-party dependencies (urllib only).

  Wazuh -> OpenCTI : looks up IOCs found in the alert (indicators + observables)
  OpenCTI -> Wazuh : sends enriched `opencti` events back through the Wazuh socket
  Wazuh -> OpenCTI : creates STIX sightings (deduplicated) for matched indicators

IOC sources: Sysmon (1,3,6,7,15,22,23-25), syscheck file + registry (incl. hash-named
files / BAM keys), Linux auditd (execve + SYSCALL-only/proctitle fallback), IDS/Packetbeat DNS,
osquery, and generic srcip/dstip fields (sshd, firewall, web...).

Install (on the Wazuh manager):
  /var/ossec/integrations/custom-opencti             shell wrapper
  /var/ossec/integrations/custom-opencti.py          this file
  /var/ossec/integrations/custom-opencti.conf.json   optional per-deployment overrides
  chown root:wazuh custom-opencti* ; chmod 750 custom-opencti*
  See wazuh/ossec/integration-opencti.xml for the <integration> block.

Arguments from Wazuh integratord:  <alert_file> <api_key> <hook_url> [debug]
  api_key  : OpenCTI API token  (if empty or "-", read /var/ossec/integrations/.opencti_token)
  hook_url : OpenCTI GraphQL endpoint, e.g. http://OPENCTI_HOST:8080/graphql

Output events keep the stock schema {"integration":"opencti","opencti":{...}} so the
rules in wazuh/rules/0100-opencti-rules.xml (100210-100222) fire on them.
"""

import sys
import os
import re
import json
import time
import ssl
import fcntl
import ipaddress
import traceback
import urllib.request
import urllib.error
from contextlib import contextmanager
from datetime import datetime, timezone
from socket import socket, AF_UNIX, SOCK_DGRAM

# ── CONFIGURATION ───────────────────────────────────────────────────────────
MIN_SCORE                         = 30     # ignore indicators scored below this
MAX_IOCS_PER_ALERT                = 12     # cap on lookups per alert (hashes/URLs/IPs are prioritised)
MAX_IND_ALERTS                    = 3      # max direct-indicator events per IOC
MAX_OBS_ALERTS                    = 3      # max observable events per IOC
HTTP_TIMEOUT                      = 20
VERIFY_TLS                        = True   # set False only for self-signed HTTPS in a lab
CREATE_SIGHTINGS                  = True
SIGHTING_CONFIDENCE               = 75
SIGHTING_DEDUPE_SECONDS           = 3600   # one sighting per (indicator, agent) per window
WAZUH_IDENTITY_ID                 = ""     # optional: existing OpenCTI identity UUID to use as sighting target
WAZUH_IDENTITY_NAME               = "Wazuh SIEM"  # found or created (as a System) if no ID is set
EMIT_OBSERVABLE_WITHOUT_INDICATOR = False  # observable exists in OpenCTI but has no indicator (weak signal)
LOOKUP_HOSTNAMES                  = False  # also query Hostname observables for every domain (doubles queries)
EXTRACT_GENERIC_IPS               = True   # also look up public data.srcip/dstip/src_ip/dest_ip (sshd, firewall, web alerts)
SIGHTING_IOC_TYPES = {'sha256', 'sha1', 'md5', 'ipv4', 'ipv6', 'domain', 'hostname', 'url'}  # filenames never create sightings
# ────────────────────────────────────────────────────────────────────────────

PWD         = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE    = f"{PWD}/logs/integrations.log"
SOCKET_ADDR = f"{PWD}/queue/sockets/queue"
STATE_FILE  = f"{PWD}/tmp/opencti_integration_state.json"
TOKEN_FILE  = f"{PWD}/integrations/.opencti_token"
CONF_FILE   = f"{PWD}/integrations/custom-opencti.conf.json"

_CONF_KEYS = (
    "MIN_SCORE", "MAX_IOCS_PER_ALERT", "MAX_IND_ALERTS", "MAX_OBS_ALERTS", "HTTP_TIMEOUT",
    "VERIFY_TLS", "CREATE_SIGHTINGS", "SIGHTING_CONFIDENCE", "SIGHTING_DEDUPE_SECONDS",
    "WAZUH_IDENTITY_ID", "WAZUH_IDENTITY_NAME", "EMIT_OBSERVABLE_WITHOUT_INDICATOR",
    "LOOKUP_HOSTNAMES", "EXTRACT_GENERIC_IPS", "SIGHTING_IOC_TYPES",
)

URL           = ''
TOKEN         = ''
DEBUG_ENABLED = False

# ── Regexes ─────────────────────────────────────────────────────────────────
regex_sha256 = re.compile(r'\b[A-Fa-f0-9]{64}\b')
regex_sha1   = re.compile(r'\b[A-Fa-f0-9]{40}\b')
regex_md5    = re.compile(r'\b[A-Fa-f0-9]{32}\b')

regex_sha256_full = re.compile(r'^[A-Fa-f0-9]{64}$')
regex_sha1_full   = re.compile(r'^[A-Fa-f0-9]{40}$')
regex_md5_full    = re.compile(r'^[A-Fa-f0-9]{32}$')

regex_ipv4      = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
regex_ipv6      = re.compile(r'(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])')
regex_domain    = re.compile(r'\b([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b')
regex_url       = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
regex_pure_ipv4 = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
regex_sysmon_hash = re.compile(r'(SHA256|SHA1|MD5)=([A-Fa-f0-9]+)', re.IGNORECASE)

sha256_sysmon_event_regex = re.compile(
    r"sysmon_(?:(?:event_?|eid)(?:1|6|7|15|23|24|25)|process-anomalies)"
)
sysmon_event3_regex  = re.compile(r"sysmon_(?:event|eid)3")
sysmon_event22_regex = re.compile(r"sysmon_(?:event22|event_22|eid22)")
dns_results_regex    = re.compile(r"type:\s*\d+\s*[^;]+|([^\s;]+)")

SYSCHECK_FILE_GROUPS     = ('syscheck_file', 'syscheck_entry_added', 'syscheck_entry_modified')
SYSCHECK_REGISTRY_GROUPS = ('syscheck_registry',)

AUDITD_MONITORED_BINS = re.compile(
    r'(?:^|/)('
    r'curl|wget|ping|ping6|nslookup|dig|host|nmap|nc|netcat|ncat|'
    r'telnet|ftp|tftp|scp|ssh|socat|tcpdump|openssl|'
    r'python[0-9.]*|php[0-9.]*|perl|bash|sh|zsh|ksh'
    r')$',
    re.IGNORECASE
)

# "word.word" tokens whose last label is really a file extension, not a TLD
NON_TLD_EXTENSIONS = {
    'py', 'sh', 'js', 'json', 'txt', 'conf', 'cfg', 'log', 'exe', 'dll', 'sys', 'bat',
    'cmd', 'ps1', 'vbs', 'xml', 'yml', 'yaml', 'ini', 'tmp', 'dat', 'db', 'so', 'jar',
    'php', 'html', 'htm', 'asp', 'aspx', 'jsp', 'pl', 'rb', 'md', 'csv', 'pdf', 'doc',
    'docx', 'xls', 'xlsx', 'zip', 'gz', 'tar', 'tgz', 'bz2', 'rpm', 'deb', 'img', 'iso',
    'bin', 'lnk', 'msi', 'scr', 'pem', 'crt', 'key', 'pid', 'lock', 'service', 'socket',
    'timer', 'bak', 'old', 'out', 'pyc', 'cpp', 'java', 'class', 'rs', 'go'
}

IOC_PRIORITY = {
    'sha256': 0, 'sha1': 0, 'md5': 0, 'url': 1, 'ipv4': 2, 'ipv6': 2,
    'domain': 3, 'hostname': 3, 'filename': 4
}


# ═══════════════════════════════════════════════════════════════════════════
# Logging / small helpers
# ═══════════════════════════════════════════════════════════════════════════

def debug(msg, do_log=False):
    if not (do_log or DEBUG_ENABLED):
        return
    now = time.strftime('%a %b %d %H:%M:%S %Z %Y')
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(f"{now}: custom-opencti: {msg}\n")
    except Exception:
        pass


def log(msg):
    debug(msg, do_log=True)


def load_conf_overrides():
    """Optional JSON file overriding the constants above (keeps the .py generic across labs)."""
    try:
        with open(CONF_FILE) as f:
            conf = json.load(f)
    except FileNotFoundError:
        return
    except Exception as e:
        log(f"Ignoring unreadable config {CONF_FILE}: {e}")
        return
    g = globals()
    for key, val in conf.items():
        if key in _CONF_KEYS:
            g[key] = set(val) if key == "SIGHTING_IOC_TYPES" else val
        elif not key.startswith("_"):
            log(f"Unknown config key ignored: {key}")


def remove_empties(value):
    def empty(v):
        return False if isinstance(v, bool) else not bool(v)

    if isinstance(value, list):
        return [x for x in (remove_empties(x) for x in value) if not empty(x)]
    if isinstance(value, dict):
        return {
            k: v for (k, v) in ((k, remove_empties(v)) for k, v in value.items())
            if not empty(v)
        }
    return value


def simplify_objectlist(output, listKey, valueKey, newKey):
    if listKey not in output or output[listKey] is None:
        output[newKey] = []
        return
    if isinstance(output[listKey], dict) and 'edges' in output[listKey]:
        edges = output[listKey]['edges']
        output[newKey] = [item[valueKey] for edge in edges for _, item in edge.items()]
    else:
        output[newKey] = [item[valueKey] for item in output[listKey]]
    if newKey != listKey and listKey in output:
        del output[listKey]


def dashboard_base():
    return (URL[:-len('graphql')] if URL.endswith('graphql') else URL.rstrip('/') + '/')


def indicator_link(indicator):
    return dashboard_base() + f"dashboard/observations/indicators/{indicator['id']}"


# ═══════════════════════════════════════════════════════════════════════════
# OpenCTI GraphQL client (urllib only)
# ═══════════════════════════════════════════════════════════════════════════

class OpenCTIConnectionError(Exception):
    pass


class OpenCTIParseError(Exception):
    pass


def _ssl_context():
    ctx = ssl.create_default_context()
    if not VERIFY_TLS:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def gql(query, variables=None):
    body = json.dumps({'query': query, 'variables': variables or {}}).encode()
    req = urllib.request.Request(
        URL, data=body, method='POST',
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {TOKEN}',
            'Accept': '*/*',
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=_ssl_context()) as r:
            raw = r.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        raise OpenCTIConnectionError(f"HTTP {e.code} from OpenCTI")
    except urllib.error.URLError as e:
        raise OpenCTIConnectionError(f"Cannot connect to OpenCTI: {e.reason}")
    except Exception as e:
        raise OpenCTIConnectionError(f"Request failed: {e}")
    try:
        return json.loads(raw)
    except ValueError:
        raise OpenCTIParseError("Invalid JSON from OpenCTI")


IOC_QUERY = '''
fragment Labels on StixCoreObject {
  objectLabel { value }
}

fragment Object on StixCoreObject {
  id
  type: entity_type
  created_at
  updated_at
  createdBy {
    ... on Identity { id standard_id identity_class name }
    ... on Organization { x_opencti_organization_type x_opencti_reliability }
    ... on Individual { x_opencti_firstname x_opencti_lastname }
  }
  ...Labels
  externalReferences { edges { node { url } } }
}

fragment IndShort on Indicator {
  id name valid_until revoked confidence
  x_opencti_score x_opencti_detection
  indicator_types x_mitre_platforms
  pattern_type pattern
  ...Labels
  killChainPhases { kill_chain_name }
}

fragment IndLong on Indicator { ...Object ...IndShort }

fragment Indicators on StixCyberObservable {
  indicators { edges { node { ...IndShort } } }
}

fragment PageInfo on PageInfo {
  startCursor endCursor hasNextPage hasPreviousPage globalCount
}

fragment NameRelation on StixObjectOrStixRelationshipOrCreator {
  ... on DomainName { id value ...Indicators }
  ... on Hostname   { id value ...Indicators }
}

fragment AddrRelation on StixObjectOrStixRelationshipOrCreator {
  ... on IPv4Addr { id value ...Indicators }
  ... on IPv6Addr { id value ...Indicators }
}

query IoCs($obs: FilterGroup, $ind: FilterGroup) {
  indicators(filters: $ind, first: 10) {
    edges { node { ...IndLong } }
    pageInfo { ...PageInfo }
  }
  stixCyberObservables(filters: $obs, first: 10) {
    edges {
      node {
        ...Object
        observable_value
        x_opencti_description
        x_opencti_score
        ...Indicators
        ... on DomainName {
          value
          stixCoreRelationships(toTypes: ["IPv4-Addr","IPv6-Addr","Domain-Name","Hostname"]) {
            edges { node { type: toType relationship_type related: to { ...AddrRelation ...NameRelation } } }
          }
        }
        ... on Hostname {
          value
          stixCoreRelationships(toTypes: ["IPv4-Addr","IPv6-Addr","Domain-Name","Hostname"]) {
            edges { node { type: toType relationship_type related: to { ...AddrRelation ...NameRelation } } }
          }
        }
        ... on Url {
          value
          stixCoreRelationships(toTypes: ["IPv4-Addr","IPv6-Addr","Domain-Name","Hostname"]) {
            edges { node { type: toType relationship_type related: to { ...AddrRelation ...NameRelation } } }
          }
        }
        ... on IPv4Addr {
          value
          stixCoreRelationships(fromTypes: ["Domain-Name","Hostname"]) {
            edges { node { type: fromType relationship_type related: from { ...NameRelation } } }
          }
        }
        ... on IPv6Addr {
          value
          stixCoreRelationships(fromTypes: ["Domain-Name","Hostname"]) {
            edges { node { type: fromType relationship_type related: from { ...NameRelation } } }
          }
        }
        ... on StixFile {
          extensions size name
          x_opencti_additional_names
          hashes { algorithm hash }
        }
      }
    }
    pageInfo { ...PageInfo }
  }
}
'''


# ═══════════════════════════════════════════════════════════════════════════
# State (sighting dedupe + cached identity), file-locked
# ═══════════════════════════════════════════════════════════════════════════

class StateStore:
    def __init__(self, path):
        self.path = path

    @contextmanager
    def locked(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        lock = open(self.path + '.lock', 'a')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = self._load()
            yield state
            self._save(state)
        finally:
            try:
                fcntl.flock(lock, fcntl.LOCK_UN)
            finally:
                lock.close()

    def _load(self):
        try:
            with open(self.path) as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save(self, state):
        tmp = self.path + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(state, f)
        os.replace(tmp, self.path)


STATE = StateStore(STATE_FILE)


# ═══════════════════════════════════════════════════════════════════════════
# Wazuh socket
# ═══════════════════════════════════════════════════════════════════════════

def send_event(msg, agent=None):
    if not agent or agent.get('id') == '000':
        string = f"1:opencti:{json.dumps(msg)}"
    else:
        string = "1:[{0}] ({1}) {2}->opencti:{3}".format(
            agent.get('id'), agent.get('name'), agent.get('ip', 'any'), json.dumps(msg)
        )
    debug("# Event:")
    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    try:
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
    finally:
        sock.close()


def send_error_event(msg, agent=None):
    try:
        send_event({'integration': 'opencti',
                    'opencti': {'error': msg, 'event_type': 'error'}}, agent)
    except Exception as e:
        log(f"Could not send error event: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# IOC extraction
# ═══════════════════════════════════════════════════════════════════════════

def format_dns_results(results):
    def unmap_ipv6(addr):
        if isinstance(addr, ipaddress.IPv4Address):
            return addr
        v4 = addr.ipv4_mapped
        return v4 if v4 else addr

    try:
        results = list(filter(len, dns_results_regex.findall(results)))
        results = [unmap_ipv6(ipaddress.ip_address(x)).exploded for x in results]
        return [x for x in results if ipaddress.ip_address(x).is_global]
    except Exception:
        return []


def packetbeat_dns(alert):
    try:
        d = alert.get('data', {})
        return 'method' in d and 'dns' in d and d['method'] == 'QUERY'
    except Exception:
        return False


def filter_packetbeat_dns(answers):
    out = []
    for r in answers:
        try:
            if r.get('type') in ('A', 'AAAA') and ipaddress.ip_address(r.get('data', '')).is_global:
                out.append(r['data'])
        except Exception:
            pass
    return out


def _plausible_domain(d):
    if not d or '.' not in d or regex_pure_ipv4.match(d):
        return False
    if d.endswith(('.local', '.lan', '.localdomain', '.internal', '.arpa')):
        return False
    tld = d.rsplit('.', 1)[-1]
    if not tld.isalpha() or len(tld) < 2 or tld in NON_TLD_EXTENSIONS:
        return False
    return True


def add_text_iocs(text, add):
    """Pull URLs, public IPs and plausible domains out of free text."""
    if not text or not isinstance(text, str):
        return

    for m in regex_url.findall(text):
        add('url', m.rstrip('.,;)'))

    for ip_s in regex_ipv4.findall(text):
        try:
            if ipaddress.ip_address(ip_s).is_global:
                add('ipv4', ip_s)
        except Exception:
            pass

    for ip_s in regex_ipv6.findall(text):
        try:
            if ipaddress.ip_address(ip_s).is_global:
                add('ipv6', ip_s)
        except Exception:
            pass

    for dom in regex_domain.findall(text):
        d = dom.strip().lower().strip('.')
        if _plausible_domain(d):
            add('domain', d)
            if LOOKUP_HOSTNAMES:
                add('hostname', d)


def _extract_hash_from_path(path, add):
    """If a file's basename (sans extension) is itself a hash (MalwareBazaar style, BAM keys)."""
    if not path or not isinstance(path, str):
        return
    basename = os.path.basename(path.replace('\\', '/'))
    name_no_ext = os.path.splitext(basename)[0]
    if regex_sha256_full.match(name_no_ext):
        add('sha256', name_no_ext)
    elif regex_sha1_full.match(name_no_ext):
        add('sha1', name_no_ext)
    elif regex_md5_full.match(name_no_ext):
        add('md5', name_no_ext)


def _build_execve_string(execve):
    try:
        keys = sorted(execve.keys(), key=lambda k: int(k[1:]) if k[1:].isdigit() else 0)
        return ' '.join(str(execve[k]) for k in keys)
    except Exception:
        return str(execve)


def _is_monitored_auditd_bin(binary):
    try:
        return bool(AUDITD_MONITORED_BINS.search(binary))
    except Exception:
        return False


def _extract_auditd_iocs(data, alert, add):
    audit   = data.get('audit', {})
    execve  = audit.get('execve', {})
    command = audit.get('command', '')
    exe     = audit.get('exe', '')

    bin_to_check = execve.get('a0', '') if execve else command
    if not bin_to_check:
        debug("# auditd: no binary in execve.a0 or audit.command, skipping")
        return
    if not _is_monitored_auditd_bin(bin_to_check):
        debug(f"# auditd skipped, not in monitored list: {bin_to_check}")
        return

    debug(f"# auditd monitored binary: {bin_to_check} (exe={exe})")

    if execve:  # Case A: full correlated event
        cmd_string = _build_execve_string(execve)
        add_text_iocs(cmd_string, add)
    else:       # Case B: SYSCALL-only event, use full_log / proctitle hex
        full_log = alert.get('full_log', '') or ''
        add_text_iocs(full_log, add)
        m = re.search(r'proctitle=([0-9A-Fa-f]+)', full_log)
        if m:
            try:
                decoded = bytes.fromhex(m.group(1)).replace(b'\x00', b' ').decode('utf-8', errors='ignore')
                debug(f"# auditd proctitle decoded: {decoded}")
                add_text_iocs(decoded, add)
            except Exception:
                pass


def extract_iocs(alert):
    iocs   = []
    groups = alert.get('rule', {}).get('groups', []) or []
    data   = alert.get('data', {}) or {}

    def add(t, v):
        if v and isinstance(v, str):
            iocs.append({'type': t, 'value': v})

    # Syscheck FILE
    if any(g in groups for g in SYSCHECK_FILE_GROUPS) and 'syscheck' in alert:
        sc = alert['syscheck']
        path = sc.get('path', '')
        add('filename', path)
        for alg in ('sha256', 'sha1', 'md5'):
            add(alg, sc.get(f'{alg}_after'))
            add(alg, sc.get(f'{alg}_before'))
        _extract_hash_from_path(path, add)

    # Syscheck REGISTRY
    if any(g in groups for g in SYSCHECK_REGISTRY_GROUPS) and 'syscheck' in alert:
        sc = alert['syscheck']
        value_name = sc.get('value_name', '')
        if value_name:
            add('filename', value_name)
            _extract_hash_from_path(value_name, add)
        for alg in ('sha256', 'sha1', 'md5'):
            add(alg, sc.get(f'{alg}_after'))

    # Sysmon hashes / filenames / command lines
    if any(sha256_sysmon_event_regex.match(g) for g in groups):
        try:
            hashes = data['win']['eventdata'].get('hashes', '') or ''
            for alg, val in regex_sysmon_hash.findall(hashes):
                add(alg.lower(), val)
        except Exception:
            pass
        try:
            ev = data['win']['eventdata']
            img = ev.get('image') or ev.get('Image')
            tgt = ev.get('TargetFilename') or ev.get('targetFilename')
            add('filename', img)
            add('filename', tgt)
            _extract_hash_from_path(img or '', add)
            _extract_hash_from_path(tgt or '', add)
            cmd = ev.get('commandLine') or ev.get('CommandLine') or ''
            parent_cmd = ev.get('parentCommandLine') or ev.get('ParentCommandLine') or ''
            for text in (cmd, parent_cmd):
                add_text_iocs(text, add)
        except Exception:
            pass

    # Sysmon event 3 (network connection)
    if any(sysmon_event3_regex.match(g) for g in groups):
        for k in ('destinationIp', 'DestinationIp', 'dest_ip', 'dstip'):
            try:
                v = data['win']['eventdata'].get(k) if 'win' in data else data.get(k)
                if v:
                    ip = ipaddress.ip_address(v)
                    if ip.is_global:
                        add('ipv6' if ip.version == 6 else 'ipv4', v)
                    break
            except Exception:
                continue

    # Sysmon event 22 (DNS query)
    if any(sysmon_event22_regex.match(g) for g in groups):
        try:
            ev = data['win']['eventdata']
            q = ev.get('queryName')
            if q:
                add('domain', q)
                if LOOKUP_HOSTNAMES:
                    add('hostname', q)
            for r in format_dns_results(ev.get('queryResults', '')):
                ip = ipaddress.ip_address(r)
                add('ipv6' if ip.version == 6 else 'ipv4', r)
        except Exception:
            pass

    # IDS / network devices
    if 'ids' in groups:
        if packetbeat_dns(alert):
            try:
                q = data['dns']['question']['name']
                add('domain', q)
                if LOOKUP_HOSTNAMES:
                    add('hostname', q)
                for a in filter_packetbeat_dns(data['dns'].get('answers', [])):
                    ip = ipaddress.ip_address(a)
                    add('ipv6' if ip.version == 6 else 'ipv4', a)
            except Exception:
                pass
        else:
            for k in ('dest_ip', 'dstip', 'src_ip', 'srcip'):
                v = data.get(k)
                try:
                    if v:
                        ip = ipaddress.ip_address(v)
                        if ip.is_global:
                            add('ipv6' if ip.version == 6 else 'ipv4', v)
                except Exception:
                    pass

    # osquery
    if any(x in groups for x in ('osquery', 'osquery_file')):
        try:
            cols = data['osquery']['columns']
            add('sha256', cols.get('sha256'))
            add('filename', cols.get('path') or cols.get('name'))
        except Exception:
            pass

    # auditd
    if ('audit_command' in groups or 'auditd' in groups or 'audit' in groups) and 'audit' in data:
        _extract_auditd_iocs(data, alert, add)

    # Generic network fields (sshd, firewall, web server... alerts routed to this integration)
    if EXTRACT_GENERIC_IPS:
        for k in ('srcip', 'dstip', 'src_ip', 'dst_ip', 'dest_ip', 'remote_ip'):
            v = data.get(k)
            try:
                if v and isinstance(v, str):
                    ip = ipaddress.ip_address(v)
                    if ip.is_global:
                        add('ipv6' if ip.version == 6 else 'ipv4', v)
            except Exception:
                pass

    # Deduplicate, then prioritise so the cap drops filenames/domains first, not hashes
    seen, out = set(), []
    for x in iocs:
        key = (x['type'], x['value'])
        if key not in seen:
            seen.add(key)
            out.append(x)
    out.sort(key=lambda x: IOC_PRIORITY.get(x['type'], 9))
    return out


# ═══════════════════════════════════════════════════════════════════════════
# Indicator ranking / shaping
# ═══════════════════════════════════════════════════════════════════════════

def _score(ind):
    try:
        return int(ind.get('x_opencti_score') or 0)
    except Exception:
        return 0


def _is_expired(valid_until):
    if not valid_until:
        return False
    try:
        dt = datetime.strptime(valid_until[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
        return dt <= datetime.now(timezone.utc)
    except Exception:
        return False


def indicator_sort_func(x):
    return (
        bool(x.get('revoked', False)),
        not x.get('x_opencti_detection', False),
        -_score(x),
        -int(x.get('confidence', 0) or 0),
        _is_expired(x.get('valid_until')),
    )


def sort_indicators(indicators):
    return sorted(indicators, key=indicator_sort_func)


def indicator_usable(ind):
    return bool(ind) and not ind.get('revoked', False) and _score(ind) >= MIN_SCORE


def modify_indicator(indicator):
    if indicator:
        simplify_objectlist(indicator, 'objectLabel', 'value', 'labels')
        simplify_objectlist(indicator, 'killChainPhases', 'kill_chain_name', 'killChainPhases')
        if 'externalReferences' in indicator:
            simplify_objectlist(indicator, 'externalReferences', 'url', 'externalReferences')
    return indicator


def modify_observable(observable, indicators):
    observable['observable_link'] = dashboard_base() + f"dashboard/observations/observables/{observable['id']}"
    simplify_objectlist(observable, 'externalReferences', 'url', 'externalReferences')
    simplify_objectlist(observable, 'objectLabel', 'value', 'labels')

    observable['indicator'] = next(iter(indicators), None)
    observable['multipleIndicators'] = len(indicators) > 1
    if observable['indicator']:
        observable['indicator_link'] = indicator_link(observable['indicator'])
    modify_indicator(observable['indicator'])

    observable.pop('indicators', None)
    observable.pop('stixCoreRelationships', None)


def relationship_with_indicators(node):
    """Best related observable (e.g. IP resolved from a bad domain) that has a usable indicator."""
    related = []
    try:
        for rel in (node.get('stixCoreRelationships') or {}).get('edges', []):
            relnode = rel.get('node', {})
            relto = relnode.get('related') or {}
            ind_edges = (relto.get('indicators') or {}).get('edges', [])
            inds = [i for i in sort_indicators([x['node'] for x in ind_edges]) if indicator_usable(i)]
            if not inds:
                continue
            best = modify_indicator(inds[0])
            item = dict(
                id=relto.get('id'),
                type=relnode.get('type'),
                relationship=relnode.get('relationship_type'),
                value=relto.get('value'),
                indicator=best,
                multipleIndicators=len(inds) > 1,
                indicator_link=indicator_link(best),
            )
            related.append(item)
    except Exception:
        pass
    related.sort(key=lambda x: indicator_sort_func(x['indicator']))
    return related[0] if related else None


# ═══════════════════════════════════════════════════════════════════════════
# Event context
# ═══════════════════════════════════════════════════════════════════════════

def add_context(source_event, event):
    event.setdefault('opencti', {})
    event['opencti'].setdefault('source', {})
    src = event['opencti']['source']

    src['alert_id'] = source_event.get('id')
    src['rule_id']  = source_event.get('rule', {}).get('id')

    if source_event.get('location'):
        src['location'] = source_event.get('location')
    if source_event.get('full_log'):
        src['full_log'] = str(source_event.get('full_log'))[:2000]

    if 'syscheck' in source_event:
        sc = source_event['syscheck']
        src['file']          = sc.get('path')
        src['value_name']    = sc.get('value_name')
        for alg in ('md5', 'sha1', 'sha256'):
            src[f'{alg}_before'] = sc.get(f'{alg}_before')
            src[f'{alg}_after']  = sc.get(f'{alg}_after')
            src[alg]             = sc.get(f'{alg}_after')

    alert_data = source_event.get('data', {}) or {}
    for key in [
        'in_iface', 'srcintf', 'src_ip', 'srcip', 'src_mac', 'srcmac',
        'src_port', 'srcport', 'dest_ip', 'dstip', 'dst_mac', 'dstmac',
        'dest_port', 'dstport', 'dstintf', 'proto', 'app_proto'
    ]:
        if key in alert_data:
            src[key] = alert_data[key]

    if packetbeat_dns(source_event):
        try:
            src['queryName'] = alert_data['dns']['question']['name']
            if 'answers' in alert_data['dns']:
                src['queryResults'] = ';'.join(x.get('data', '') for x in alert_data['dns']['answers'])
        except Exception:
            pass

    if 'win' in alert_data and 'eventdata' in alert_data['win']:
        ev = alert_data['win']['eventdata']
        for key in ['queryName', 'queryResults', 'image', 'DestinationIp', 'destinationIp',
                    'TargetFilename', 'targetFilename', 'commandLine', 'parentCommandLine']:
            if key in ev:
                src[key] = ev[key]

    if 'audit' in alert_data:
        audit = alert_data['audit']
        execve = audit.get('execve', {})
        if execve:
            src['execve'] = _build_execve_string(execve)
        elif audit.get('command'):
            src['execve'] = audit.get('command')
        if audit.get('exe'):
            src['exe'] = audit.get('exe')


# ═══════════════════════════════════════════════════════════════════════════
# Lookup
# ═══════════════════════════════════════════════════════════════════════════

def ind_ip_pattern(string):
    ip = ipaddress.ip_address(string)
    return f"[ipv6-addr:value = '{string}']" if ip.version == 6 else f"[ipv4-addr:value = '{string}']"


def _stix_escape(v):
    return v.replace('\\', '\\\\').replace("'", "\\'")


def build_opencti_filters(ioc):
    t, v = ioc['type'], ioc['value']
    obs_key, obs_values, ind_patterns, file_names = 'value', [v], [], []

    if t in ('ipv4', 'ipv6'):
        ind_patterns = [ind_ip_pattern(v)]
    elif t == 'domain':
        ind_patterns = [f"[domain-name:value = '{_stix_escape(v)}']"]
    elif t == 'hostname':
        ind_patterns = [f"[hostname:value = '{_stix_escape(v)}']"]
    elif t == 'url':
        ind_patterns = [f"[url:value = '{_stix_escape(v)}']"]
    elif t in ('sha256', 'sha1', 'md5'):
        alg = {'sha256': 'SHA-256', 'sha1': 'SHA-1', 'md5': 'MD5'}[t]
        obs_key = f"hashes.{alg}"
        ind_patterns = [f"[file:hashes.'{alg}' = '{v}']"]
    elif t == 'filename':
        base = os.path.basename(v.replace('\\', '/')) or v
        file_names = [base]
        obs_values = [base]

    return obs_key, obs_values, ind_patterns, file_names


def lookup_ioc(alert, ioc):
    """Returns a list of (event, sighting_candidate_or_None)."""
    obs_key, obs_values, ind_filter, file_names = build_opencti_filters(ioc)
    debug(f"# Querying OpenCTI for {ioc} key={obs_key}")

    obs_groups = []
    if file_names:
        obs_groups.append({
            "mode": "or",
            "filters": [
                {"key": "name", "values": file_names},
                {"key": "x_opencti_additional_names", "values": file_names},
            ],
            "filterGroups": []
        })

    ind_var = {"mode": "and", "filterGroups": [],
               "filters": [{"key": "id", "values": ["__never__"]}]}
    if ind_filter:
        ind_var = {
            "mode": "and", "filterGroups": [],
            "filters": [
                {"key": "pattern_type", "values": ["stix"]},
                {"mode": "or", "key": "pattern", "values": ind_filter},
            ]
        }

    resp = gql(IOC_QUERY, {
        'obs': {"mode": "and", "filterGroups": obs_groups,
                "filters": [{"key": obs_key, "values": obs_values}]},
        'ind': ind_var,
    })
    debug("# Response:")
    debug(resp)

    if resp.get('errors'):
        try:
            log(f"GraphQL errors for {ioc['type']}: {resp['errors'][0].get('message')}")
        except Exception:
            log("GraphQL returned errors")

    data = resp.get('data')
    if not data:
        return []

    results = []
    direct_ids = set()

    # ── Direct indicator pattern matches ──
    if ind_filter:
        edges = (data.get('indicators') or {}).get('edges', [])
        direct = [i for i in sort_indicators([e['node'] for e in edges]) if indicator_usable(i)]
        direct_ids = {i['id'] for i in direct}
        for ind in direct[:MAX_IND_ALERTS]:
            cand = {'id': ind['id'], 'name': ind.get('name')}
            exact = ind.get('pattern') in ind_filter
            new_alert = {'integration': 'opencti', 'opencti': {
                'indicator':      modify_indicator(ind),
                'indicator_link': indicator_link(ind),
                'query_key':      obs_key,
                'query_values':   ';'.join(ind_filter),
                'event_type':     'indicator_pattern_match' if exact else 'indicator_partial_pattern_match',
            }}
            add_context(alert, new_alert)
            results.append((new_alert, cand))

    # ── Observables ──
    obs_edges = (data.get('stixCyberObservables') or {}).get('edges', [])
    for edge in obs_edges[:MAX_OBS_ALERTS]:
        node = edge['node']
        ind_edges = (node.get('indicators') or {}).get('edges', [])
        indicators = sort_indicators([x['node'] for x in ind_edges]) if ind_edges else []
        indicators = [i for i in indicators if i['id'] not in direct_ids and indicator_usable(i)]

        related = relationship_with_indicators(node)
        if related and related['indicator']['id'] in direct_ids:
            related = None

        if not indicators and not related:
            if EMIT_OBSERVABLE_WITHOUT_INDICATOR:
                new_alert = {'integration': 'opencti', 'opencti': node}
                node['related'] = None
                node['query_key'] = obs_key
                node['query_values'] = ';'.join(obs_values)
                node['event_type'] = 'observable_without_indicator'
                modify_observable(node, [])
                add_context(alert, new_alert)
                results.append((new_alert, None))
            continue

        # Sightings only for the observable's own indicator, not for related ones
        cand = {'id': indicators[0]['id'], 'name': indicators[0].get('name')} if indicators else None

        new_alert = {'integration': 'opencti', 'opencti': node}
        node['related'] = related
        node['query_key'] = obs_key
        node['query_values'] = ';'.join(obs_values)
        node['event_type'] = 'observable_with_indicator' if indicators else 'observable_with_related_indicator'
        modify_observable(node, indicators)
        add_context(alert, new_alert)
        results.append((new_alert, cand))

    return results


# ═══════════════════════════════════════════════════════════════════════════
# Sightings (OpenCTI write path)
# ═══════════════════════════════════════════════════════════════════════════

def _gql_str(value):
    """JSON string literal == valid GraphQL string literal (handles quotes/backslashes/unicode)."""
    return json.dumps(str(value))


def _find_identity(name):
    # Inline literal on purpose: variables inside these filter literals returned nothing on the lab OpenCTI
    r = gql('query { identities(filters: {mode: and, filters: [{key: "name", values: [%s]}], '
            'filterGroups: []}, first: 1) { edges { node { id name } } } }' % _gql_str(name))
    edges = ((r.get('data') or {}).get('identities') or {}).get('edges', [])
    return edges[0]['node']['id'] if edges else None


def _create_system_identity(name):
    desc = "Created by the Wazuh-OpenCTI integration"
    # Form proven on the lab (writeup, bug 4): inline identityAdd with type "System"
    r = gql('mutation { identityAdd(input: {type: "System", name: %s, description: %s}) { id } }'
            % (_gql_str(name), _gql_str(desc)))
    iid = ((r.get('data') or {}).get('identityAdd') or {}).get('id')
    if iid:
        return iid
    # Fallback for OpenCTI versions that expose a dedicated System mutation
    r = gql('mutation { systemAdd(input: {name: %s, description: %s}) { id } }'
            % (_gql_str(name), _gql_str(desc)))
    return ((r.get('data') or {}).get('systemAdd') or {}).get('id')


def resolve_identity(cached):
    if WAZUH_IDENTITY_ID:
        return WAZUH_IDENTITY_ID
    if cached:
        return cached
    iid = _find_identity(WAZUH_IDENTITY_NAME) or _create_system_identity(WAZUH_IDENTITY_NAME)
    if iid:
        with STATE.locked() as st:
            st['identity_id'] = iid
    return iid


def _alert_timestamp(alert):
    raw = alert.get('timestamp') or ''
    try:
        raw = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', raw)
        dt = datetime.fromisoformat(raw.replace('Z', '+00:00'))
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
    except Exception:
        dt = datetime.now(timezone.utc)
    return dt.isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def maybe_create_sighting(alert, ioc, cand):
    agent = alert.get('agent') or {}
    agent_id = agent.get('id', '000')
    key = f"{cand['id']}|{agent_id}"
    now = time.time()

    # Reserve the dedupe slot first, under lock
    try:
        with STATE.locked() as st:
            seen = st.setdefault('sightings', {})
            last = seen.get(key)
            if last and now - last < SIGHTING_DEDUPE_SECONDS:
                debug(f"# sighting deduped for {key}")
                return None
            seen[key] = now
            for k in [k for k, v in seen.items() if now - v > 86400]:
                del seen[k]
            cached_identity = st.get('identity_id')
    except Exception as e:
        log(f"State file unavailable ({STATE_FILE}): {e}. Sighting skipped to avoid duplicates.")
        return None

    sighting_id = None
    try:
        identity_id = resolve_identity(cached_identity)
        if not identity_id:
            log("Could not resolve a sighting identity in OpenCTI")
        else:
            ts = _alert_timestamp(alert)
            rule = alert.get('rule', {})
            desc = (f"Observed by Wazuh on agent {agent.get('name', 'unknown')} "
                    f"({agent.get('ip', 'n/a')}). {ioc['type']}={ioc['value']}. "
                    f"Rule {rule.get('id', '?')}: {rule.get('description', '')}")[:1000]
            r = gql('''
            mutation CreateSighting(
              $fromId: StixRef!, $toId: StixRef!, $description: String!,
              $first_seen: DateTime!, $last_seen: DateTime!
            ) {
              stixSightingRelationshipAdd(input: {
                fromId: $fromId, toId: $toId, description: $description,
                first_seen: $first_seen, last_seen: $last_seen,
                attribute_count: 1, confidence: %d
              }) { id }
            }''' % int(SIGHTING_CONFIDENCE), {
                "fromId": cand['id'], "toId": identity_id, "description": desc,
                "first_seen": ts, "last_seen": ts,
            })
            sighting_id = ((r.get('data') or {}).get('stixSightingRelationshipAdd') or {}).get('id')
            if sighting_id:
                log(f"Sighting created: {sighting_id} (indicator {cand['id']}, agent {agent.get('name')})")
            else:
                errs = [e.get('message') for e in (r.get('errors') or [])][:2]
                log(f"Sighting failed: {errs}")
                if cached_identity and not WAZUH_IDENTITY_ID:
                    with STATE.locked() as st:   # cached identity may have been deleted
                        st.pop('identity_id', None)
    except (OpenCTIConnectionError, OpenCTIParseError) as e:
        log(f"Sighting request failed: {e}")
    except Exception as e:
        log(f"Sighting error: {e}")

    if not sighting_id:  # release the slot so a later alert can retry
        try:
            with STATE.locked() as st:
                st.get('sightings', {}).pop(key, None)
        except Exception:
            pass
    return sighting_id


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

def process_alert(alert):
    agent = alert.get('agent')
    groups = alert.get('rule', {}).get('groups', []) or []
    iocs = extract_iocs(alert)

    if not iocs:
        debug(f"# No IOCs extracted for groups={groups}, skipping")
        return

    if len(iocs) > MAX_IOCS_PER_ALERT:
        debug(f"# {len(iocs)} IOCs extracted, truncating to {MAX_IOCS_PER_ALERT}")
    sighted = set()

    for ioc in iocs[:MAX_IOCS_PER_ALERT]:
        try:
            results = lookup_ioc(alert, ioc)
        except OpenCTIConnectionError as e:
            log(str(e))
            send_error_event(f"OpenCTI unreachable: {e}", agent)
            return  # no point retrying the remaining IOCs
        except OpenCTIParseError as e:
            log(str(e))
            send_error_event("Failed to parse response from OpenCTI API", agent)
            continue

        for event, cand in results:
            if (CREATE_SIGHTINGS and cand and ioc['type'] in SIGHTING_IOC_TYPES
                    and cand['id'] not in sighted):
                sighted.add(cand['id'])
                sid = maybe_create_sighting(alert, ioc, cand)
                if sid:
                    event['opencti']['sighting_id'] = sid
            send_event(remove_empties(event), agent)


def read_token_file():
    try:
        with open(TOKEN_FILE) as f:
            return f.read().strip()
    except Exception:
        return ''


def main(args):
    global URL, TOKEN, DEBUG_ENABLED
    load_conf_overrides()
    alert_path    = args[1]
    TOKEN         = args[2]
    URL           = args[3]
    DEBUG_ENABLED = len(args) > 4 and args[4] == 'debug'

    if TOKEN in ('', '-'):
        TOKEN = read_token_file()
    if not TOKEN:
        log("No OpenCTI token supplied (argv[2] or token file)")
        sys.exit(1)

    debug(f"# Starting, alert_path={alert_path}, url={URL}")

    with open(alert_path, errors='ignore') as f:
        alert = json.load(f)

    process_alert(alert)


if __name__ == '__main__':
    try:
        if len(sys.argv) < 4:
            log(f"Incorrect arguments (got {len(sys.argv) - 1}, need alert_file token url)")
            sys.exit(1)
        main(sys.argv)
    except Exception as e:
        debug(str(e), do_log=True)
        debug(traceback.format_exc(), do_log=True)
        raise
