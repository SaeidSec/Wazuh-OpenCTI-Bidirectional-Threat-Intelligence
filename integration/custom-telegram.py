#!/usr/bin/env python3
"""
Wazuh -> Telegram alert notifier (zero dependencies).

NOTE: reconstructed from the AegisryxLabs writeup (Part 8) - the original script was not in the
uploaded files. Review before relying on it.

Arguments from integratord: <alert_file> <api_key> <hook_url>
  hook_url = https://api.telegram.org/bot<BOT_TOKEN>      (the bot token lives only in ossec.conf)
Settings (chat id, minimum level...) come from custom-telegram.conf.json next to this script.
"""
import sys, os, json, ssl, html, time, traceback
import urllib.parse, urllib.request

PWD = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f"{PWD}/logs/integrations.log"
CONF_FILE = f"{PWD}/integrations/custom-telegram.conf.json"
DEFAULTS = {"chat_id": "", "min_level": 5, "only_groups": [], "verify_tls": True, "timeout": 10}


def log(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{time.strftime('%a %b %d %H:%M:%S %Z %Y')}: custom-telegram: {msg}\n")
    except Exception:
        pass


def load_conf():
    conf = dict(DEFAULTS)
    try:
        with open(CONF_FILE) as f:
            conf.update({k: v for k, v in json.load(f).items() if k in DEFAULTS})
    except FileNotFoundError:
        pass
    except Exception as e:
        log(f"unreadable config: {e}")
    return conf


def esc(v):
    return html.escape(str(v), quote=False)


def build_message(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {}) or {}
    lines = [
        f"\U0001F6A8 <b>Wazuh alert - level {esc(rule.get('level', '?'))}</b>",
        f"<b>{esc(rule.get('description', 'no description'))}</b>",
        f"Rule: {esc(rule.get('id', '?'))}   Agent: {esc(agent.get('name', 'manager'))} ({esc(agent.get('ip', 'n/a'))})",
        f"Time: {esc(alert.get('timestamp', ''))}",
    ]
    oc = data.get("opencti")
    if isinstance(oc, dict):
        ind = oc.get("indicator") or {}
        lines.append("")
        lines.append(f"<b>OpenCTI</b> {esc(oc.get('event_type', ''))}")
        if ind.get("name"):
            lines.append(f"Indicator: {esc(ind['name'])}  score: {esc(ind.get('x_opencti_score', '?'))}")
        if ind.get("labels"):
            lines.append("Labels: " + esc(", ".join(map(str, ind["labels"]))))
        if oc.get("query_values"):
            lines.append(f"IOC: {esc(oc['query_values'])}")
        if oc.get("sighting_id"):
            lines.append("Sighting recorded in OpenCTI")
        if ind.get("id") and oc.get("indicator_link"):
            lines.append(esc(oc["indicator_link"]))
    return "\n".join(lines)[:3800]


def main(argv):
    if len(argv) < 4:
        log("incorrect arguments (need alert_file api_key hook_url)")
        return 1
    with open(argv[1], errors="ignore") as f:
        alert = json.load(f)
    conf = load_conf()
    if not conf["chat_id"]:
        log("chat_id not configured - nothing sent")
        return 1
    rule = alert.get("rule", {})
    try:
        if int(rule.get("level", 0)) < int(conf["min_level"]):
            return 0
    except Exception:
        pass
    if conf["only_groups"] and not set(conf["only_groups"]) & set(rule.get("groups", []) or []):
        return 0

    ctx = ssl.create_default_context()
    if not conf["verify_tls"]:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    body = urllib.parse.urlencode({
        "chat_id": conf["chat_id"], "text": build_message(alert),
        "parse_mode": "HTML", "disable_web_page_preview": "true",
    }).encode()
    req = urllib.request.Request(argv[3].rstrip("/") + "/sendMessage", data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=conf["timeout"], context=ctx) as r:
            if r.status != 200:
                log(f"telegram returned HTTP {r.status}")
    except Exception as e:  # never log the URL - it contains the bot token
        log(f"send failed: {type(e).__name__}")
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as e:
        log(f"{e}\n{traceback.format_exc()}")
        raise
