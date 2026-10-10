# Deployment guide

Run all `Wazuh manager` steps as root on the manager. Paths assume a default `/var/ossec` install.

## 0. Prerequisites

- OpenCTI reachable from the Wazuh manager (default `http://<host>:8080`), with at least one feed ingesting.
- Wazuh manager + indexer + dashboard running; agents enrolled.
- Python 3 on the manager is enough. The script uses only the standard library, so nothing has to be
  installed into `/var/ossec/framework/python`.

## 1. OpenCTI

Follow [../opencti/INSTALL.md](../opencti/INSTALL.md) and fill `opencti/env.example` as `.env`
(generate every secret yourself with `uuidgen` / `openssl rand`).

Then in the OpenCTI UI:

1. Enable feed connectors (AlienVault OTX, AbuseIPDB, MalwareBazaar, abuse.ch, ...) and confirm data arrives
   under Observations.
2. Create a dedicated user for Wazuh and copy its API token (Profile -> API access).
3. Optional: create a **System** identity named `Wazuh SIEM` (Entities -> Systems). Its UUID goes in
   `WAZUH_IDENTITY_ID`. If you skip this, the script finds or creates the identity itself on the first sighting
   and caches the ID in `/var/ossec/tmp/opencti_integration_state.json`.

## 2. Wazuh manager: agent groups

```bash
/var/ossec/bin/agent_groups -a -g windows -q
/var/ossec/bin/agent_groups -a -g linux -q
cp wazuh/agent-groups/windows-agent.conf /var/ossec/etc/shared/windows/agent.conf
cp wazuh/agent-groups/linux-agent.conf   /var/ossec/etc/shared/linux/agent.conf
chown wazuh:wazuh /var/ossec/etc/shared/{windows,linux}/agent.conf
/var/ossec/bin/agent_groups -a -i <AGENT_ID> -g <windows|linux> -q
```

## 3. Wazuh manager: rules

```bash
cp wazuh/rules/*.xml /var/ossec/etc/rules/
chown root:wazuh /var/ossec/etc/rules/0*.xml && chmod 660 /var/ossec/etc/rules/0*.xml
/var/ossec/bin/wazuh-analysisd -t        # must finish without errors before you restart
```

Do not copy `optional/windows-process-ignore.xml` unless rule 100691 exists in your ruleset.

## 4. Endpoints

- **Windows**: [../endpoints/windows/sysmon-setup.md](../endpoints/windows/sysmon-setup.md)
- **Linux**: [../endpoints/linux/auditd-setup.md](../endpoints/linux/auditd-setup.md)
  (rules file: `endpoints/linux/command-monitor.rules`; the agent `<localfile>` reads `/var/log/audit/audit.log`).

## 5. Integration files

```bash
cd /var/ossec/integrations
cp <repo>/integration/custom-opencti       .
cp <repo>/integration/custom-opencti.py    .
cp <repo>/integration/custom-opencti.conf.example.json custom-opencti.conf.json   # edit
chown root:wazuh custom-opencti*   && chmod 750 custom-opencti custom-opencti.py
chmod 640 custom-opencti.conf.json
```

Optional Telegram: same for `custom-telegram`, `custom-telegram.py`, and `custom-telegram.conf.json`.

## 6. ossec.conf

Paste `wazuh/ossec/integration-opencti.xml` inside `<ossec_config>` of `/var/ossec/etc/ossec.conf`, put in the real
`api_key` and `hook_url`, then:

```bash
systemctl restart wazuh-manager
tail -f /var/ossec/logs/integrations.log /var/ossec/logs/ossec.log
```

Keep the token out of the XML if you prefer: set `<api_key>-</api_key>` and place the token in
`/var/ossec/integrations/.opencti_token` (`root:wazuh`, `640`).

## 7. Verify

Go to [TESTING.md](TESTING.md).

## Checklist

**Before**
- [ ] OpenCTI up, feeds ingesting, dedicated API user + token created, old tokens rotated
- [ ] Manager can reach `http://<opencti>:8080/graphql` (`curl -s -o /dev/null -w '%{http_code}' ...`)

**Manager**
- [ ] Agent groups created, agents assigned, `agent.conf` in place
- [ ] Rules copied, `wazuh-analysisd -t` clean
- [ ] `custom-opencti`, `custom-opencti.py`, conf JSON present, owner `root:wazuh`, mode 750/640
- [ ] `<integration>` block added with token + URL
- [ ] `systemctl restart wazuh-manager` succeeded

**Endpoints**
- [ ] Sysmon installed and logging (Windows)
- [ ] auditd rules loaded: `auditctl -l | grep command_monitor` (Linux)

**Validation**
- [ ] `python3 tests/test_integration.py` passes
- [ ] Manual run with a sample alert produces an `opencti` event (see TESTING.md)
- [ ] `integrations.log` shows `Sighting created`
- [ ] OpenCTI -> Events -> Sightings shows the entry
- [ ] (Optional) Telegram message received
