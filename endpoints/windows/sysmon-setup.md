# Windows endpoints: Sysmon + Wazuh agent group

1. **Install Sysmon** (Microsoft Sysinternals) on each Windows endpoint with a maintained config,
   for example SwiftOnSecurity/sysmon-config. From an elevated prompt:

   ```
   sysmon64.exe -accepteula -i sysmonconfig.xml
   ```

   Confirm events exist: Event Viewer -> Applications and Services Logs -> Microsoft -> Windows ->
   Sysmon -> Operational.

2. **Create the agent group and assign agents** (on the Wazuh manager):

   ```
   /var/ossec/bin/agent_groups -a -g windows -q
   /var/ossec/bin/agent_groups -a -i <AGENT_ID> -g windows -q
   cp wazuh/agent-groups/windows-agent.conf /var/ossec/etc/shared/windows/agent.conf
   chown wazuh:wazuh /var/ossec/etc/shared/windows/agent.conf
   ```

   That `agent.conf` collects the `Microsoft-Windows-Sysmon/Operational` and WMI-Activity event
   channels and sets up FIM for Downloads/Desktop/AppData/Run keys etc.

3. **Install the Sysmon group rules** on the manager: `wazuh/rules/0300-sysmon-event-groups.xml`
   (raises Sysmon events 1-15/22 to level 5 and tags them `sysmon_eventN`, which the
   `<integration>` block listens for).

4. Check a test event: run `nslookup example.com` on the endpoint; a Sysmon event 22 alert
   ("Sysmon - DNS Query") should appear in the Wazuh dashboard.
