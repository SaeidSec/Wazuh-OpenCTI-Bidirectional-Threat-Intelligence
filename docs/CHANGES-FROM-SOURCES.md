# Changes from the two source projects

## Script

Source A = `opencti-custom.py` (Ram Kumar repo). Source B = `custom-opencti.py` (AegisryxLabs Phase 2).

| Area | Source A | Source B | Master |
|---|---|---|---|
| IOC extraction | Strong: Sysmon, FIM, registry/BAM, auditd, IDS, osquery | Read flat keys such as `win.eventdata.image` and `syscheck.path` from `data`, which Wazuh's nested JSON does not contain, so FIM/Sysmon/auditd found nothing | A's extraction, plus generic `srcip/dstip` lookup (needed for the SSH test in the writeup) |
| Sighting write-back | None | Yes, but one per matching alert | Yes, deduplicated per indicator + agent per hour (file-locked state) |
| Dependencies | `requests` | None | None (`urllib`) |
| Token | argv (ossec.conf) | Hard-coded in the script | argv or root-only file; never logged |
| TLS | Default verification | Verification disabled unconditionally | On by default, switchable |
| Query safety | GraphQL variables | Values interpolated into query strings | Variables for the IOC query; JSON-escaped literals for identity helpers |
| Event schema | `{"integration":"opencti","opencti":{...}}` | `{"opencti_match":true,"ioc_type":...}` | A's schema (rules 100210-100222) |
| Wazuh socket message | Agent-prefixed | No prefix (appeared to come from the manager) | Agent-prefixed |
| Score filtering | None | Indicators only; observables defaulted to 50 and bypassed it | `MIN_SCORE` applies everywhere, revoked indicators dropped |
| OpenCTI outage | One error event per IOC | Silent | One error event, then stop |
| Domain false positives | `script.py`, `update.sh`, ... looked like domains | n/a | Common file extensions filtered |
| Sysmon hashes | First 32-hex string taken as MD5 (could be IMPHASH) | n/a | Parsed as `ALG=value` pairs |
| IOC cap | First 10 in discovery order | n/a | Cap 12, hashes/URLs/IPs first |
| Sort/expiry | Crashed if `valid_until` lacked fractional seconds | n/a | Tolerant parsing |

Dropped on purpose: Source B's `opencti_match` schema and its rules (100100-100108, 100300-100307), which no
longer match the events; the `<level>3` integration filter; the Phase 1 CDB sync (`opencti-wazuh-sync.py`, not
in the uploads, kept only as a concept).

## Rules and config

- **Duplicate rule IDs fixed.** `linux-ignore.md` reused 100611, 100612 and 100621 from the Windows ignore file.
  Linux rules are now 100630-100643:
  100613->100630, 100614->100631, 100615->100632, 100616->100633, 100611->100634, 100612->100635,
  100617->100636, 100618->100637, 100619->100638, 100621->100639, 100622->100640, 100623->100641,
  100624->100642, 100625->100643.
- **Rules 100620/100621 (Windows process ignore) moved to `optional/`.** Their parent, rule 100691
  (`opencti-endpoint-ioc-rules.xml`), is not in either upload. A missing `if_sid` parent prevents the ruleset from loading.
- The single `local_rules.xml` was split into numbered files by topic; rule contents are unchanged.
- The integration `<group>` list now includes both `sysmon_event22` and `sysmon_event_22` style names.
- Secrets scrubbed from `ossec-conf.md` and the OpenCTI `.env` sample.

## Not changed, but worth a look

- `linux-agent.conf` monitors `/boot` and then lists `<ignore>/boot</ignore>` and `<ignore>/boot/*</ignore>`, which cancels it. Remove the ignores if you want `/boot` monitored.
- The Windows ignore rule for `rundll32.exe`/`auditpol.exe` (100621) carries its author's own warning: blanket-ignoring them hides LOLBin abuse and log tampering (T1562.002).
- `linux-agent.conf` contains a placeholder `/etc/app.conf`.
- The two `ossec-conf.md` variants used different `hook_url` addresses (and one had no port); use one URL for your lab.

## Not in the uploads

- `custom-telegram.py`: **reconstructed** from the writeup (this package's version has not run against Telegram).
- `opencti-wazuh-sync.py` (Phase 1 CDB sync).
- `opencti-endpoint-ioc-rules.xml` (rule 100691).
- The "wire OpenCTI to the Wazuh indexer" step, which the source README marks as not yet written.
