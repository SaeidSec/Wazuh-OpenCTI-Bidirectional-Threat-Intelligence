## Linux Endpoints:
## Here's a complete step-by-step guide for auditd setup on your Linux endpoints:

**Step 1 — Check if auditd is already installed**
```bash
sudo systemctl status auditd
```
- If it shows **active (running)** → skip to Step 3
- If **not found** → go to Step 2

## Step 2 — Install auditd

**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install -y auditd audispd-plugins
```

**AlmaLinux / RHEL / CentOS:**
```bash
sudo yum install -y audit audit-libs
# or on newer versions
sudo dnf install -y audit audit-libs
```

Enable and start:
```bash
sudo systemctl enable auditd
sudo systemctl start auditd
sudo systemctl status auditd   # confirm active
```

**Step 3 — Configure auditd main config:**
```bash
sudo nano /etc/audit/auditd.conf
```

Change / confirm these values:
```bash
# How many log files to keep
num_logs = 5

# Max size per log file in MB — keep small to save storage
max_log_file = 20

# What to do when log is full — rotate is safest
max_log_file_action = ROTATE

# Where logs go (default is fine)
log_file = /var/log/audit/audit.log

# Write logs immediately (important for Wazuh)
flush = INCREMENTAL_ASYNC
```

Save and exit.

## Step 4 — Configure audisp (sends auditd logs to Wazuh)

This is what makes Wazuh actually receive the auditd events.

```bash
sudo nano /etc/audisp/plugins.d/af_unix.conf
```

Make sure it looks like this:
```bash
active = yes
direction = out
path = builtin_af_unix
type = builtin
args = 0640 /var/ossec/queue/sockets/audit
format = string
```

**Note: On newer systems (Ubuntu 22+, AlmaLinux 9) the path may be:**
```bash
sudo nano /etc/audit/plugins.d/af_unix.conf
```

**Step 5 — Create your targeted command-monitor rules**

```bash
sudo nano /etc/audit/rules.d/command-monitor.rules
```

Paste this:
```bash
## ── Wazuh OpenCTI Targeted Command Monitor Rules ──────────────────
## Only these specific binaries are logged — nothing else
## Key = command_monitor — picked up by Wazuh rule 100500

# Download tools
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/curl     -k command_monitor
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/wget     -k command_monitor

# ICMP / Ping
-a always,exit -F arch=b64 -S execve -F path=/bin/ping         -k command_monitor
-a always,exit -F arch=b64 -S execve -F path=/bin/ping6        -k command_monitor
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/ping     -k command_monitor

# DNS tools
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/nslookup -k command_monitor
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/dig      -k command_monitor
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/host     -k command_monitor

# Port scanning
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/nmap     -k command_monitor

# Reverse shell / tunneling
-a always,exit -F arch=b64 -S execve -F path=/bin/nc           -k command_monitor
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/nc       -k command_monitor
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/netcat   -k command_monitor
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/ncat     -k command_monitor
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/socat    -k command_monitor

# File transfer
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/ftp      -k command_monitor
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/tftp     -k command_monitor
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/scp      -k command_monitor

# SSH outbound
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/ssh      -k command_monitor

# Packet capture / crypto
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/tcpdump -k command_monitor
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/openssl  -k command_monitor

# Plaintext remote
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/telnet   -k command_monitor

# Scripting / interpreters
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/python3  -k command_monitor
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/python   -k command_monitor
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/php      -k command_monitor
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/perl     -k command_monitor

# Shells
-a always,exit -F arch=b64 -S execve -F path=/bin/bash         -k command_monitor
-a always,exit -F arch=b64 -S execve -F path=/bin/sh           -k command_monitor
```

Save and exit.

**Step 6 — Load rules and restart**

```bash
# Compile and load all rules from /etc/audit/rules.d/
sudo augenrules --load

# Restart auditd
sudo systemctl restart auditd

# Verify rules loaded
sudo auditctl -l | grep command_monitor
```

## Step 7 — Configure Wazuh agent to read auditd

On the **Linux agent** `ossec.conf`:

```bash
<ossec_config>
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
</ossec_config>
```

Restart the Wazuh agent:

```bash
sudo systemctl restart wazuh-agent
```

## Step 8 — Test end-to-end

Run a monitored command on the Linux endpoint:

```bash
curl -s https://example.com
```
