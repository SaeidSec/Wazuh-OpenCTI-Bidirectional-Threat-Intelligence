# Testing

## 1. Offline tests (no Wazuh, no OpenCTI)

```bash
python3 tests/test_integration.py -v
```

Starts a mock OpenCTI GraphQL server and a fake Wazuh socket, then checks IOC extraction (hash-named files,
IMPHASH, file-extension false positives, private IPs, auditd proctitle), event schema and agent prefix, score
filtering, sighting creation, **sighting dedupe**, per-agent sightings, error event when OpenCTI is down, and
the JSON config override. It verifies this project's logic, not your OpenCTI's schema.

## 2. Run the script by hand against your real OpenCTI

Pick an IP that really is an indicator in your OpenCTI (check Observations -> Indicators), put it into a copy of
`tests/alerts/sshd-bruteforce.json` (`data.srcip` and the `full_log`), then on the manager:

```bash
sudo -u wazuh /var/ossec/framework/python/bin/python3 \
  /var/ossec/integrations/custom-opencti.py ./sshd-bruteforce.json - http://OPENCTI_HOST:8080/graphql debug
tail -n 30 /var/ossec/logs/integrations.log
```

`-` makes the script read the token from `/var/ossec/integrations/.opencti_token` (or pass the token directly as the
second argument). With `debug`, the log shows each IOC queried, the raw response and the event sent.

Expected: an `opencti` event reaches analysisd, and the log has `Sighting created: <uuid>`. Then:

```bash
grep -i opencti /var/ossec/logs/alerts/alerts.json | tail -n 3
```

Rule 100212 (level 12) should be there, plus 100221 (level 14) if the indicator score is 70+.

## 3. Rule test with wazuh-logtest

```bash
echo '{"integration":"opencti","opencti":{"event_type":"indicator_pattern_match","indicator":{"name":"1.2.3.4","x_opencti_score":80},"query_values":"1.2.3.4"}}' \
  | /var/ossec/bin/wazuh-logtest
```

Expect rule 100210 -> 100212 (and 100221). If `wazuh-logtest` shows no JSON decoding, test with the live path instead.

## 4. End-to-end per source

| Source | Trigger | Needs |
|---|---|---|
| SSH source IP | `logger -p auth.info -t sshd 'Failed password for root from <IOC_IP> port 22 ssh2'` on a monitored agent | `authentication_failed,sshd` appended to the integration `<group>` list |
| auditd | `ping -c1 <IOC_IP>` or `curl -s http://<IOC_DOMAIN>/` on a Linux agent | auditd rules loaded, rules 100499/100500 installed |
| Sysmon DNS / network | `nslookup <IOC_DOMAIN>` or connect to `<IOC_IP>` on a Windows agent | Sysmon + 0300 rules |
| FIM hash | download a known-bad sample into a monitored folder (lab only) | FIM on that folder |

Verify in the OpenCTI UI: Events -> Sightings (clear the "false positive" filter if the list looks empty).

## 5. Sighting dedupe check

Trigger the same IOC twice within an hour on the same agent: two `opencti` events/alerts, one sighting.
Raise `SIGHTING_DEDUPE_SECONDS` or set it to 0 in `custom-opencti.conf.json` to change this.

## 6. Failure test

Stop OpenCTI (or break the URL) and trigger an alert: you should get exactly one rule 100211 alert
("Failed to connect to API"), not one per IOC.
