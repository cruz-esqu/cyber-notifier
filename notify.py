"""Deliver alerts to Discord, or print them to the terminal if no webhook is set."""
import time

import requests

SEVERITY_COLORS = {
    "Critical": 0xE01E37,
    "High": 0xF77F00,
    "Medium": 0xFCBF49,
    "Low": 0x4CC9F0,
}


def _cut(text, limit):
    text = text or "-"
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _bullets(items):
    return "\n".join(f"• {i}" for i in items) if items else "None provided in sources."


def build_embed(item, alert):
    cvss = item.get("cvss") or {}
    epss = item.get("epss")
    cvss_text = f"{cvss.get('score')} ({cvss.get('severity')}, v{cvss.get('version')})" if cvss else "Not yet scored"
    epss_text = f"{epss['score']:.1%} (top {100 - epss['percentile'] * 100:.0f}%)" if epss else "N/A"
    sources = "\n".join(item.get("references", [])[:5]) or "-"

    return {
        "title": _cut(f"{item['cve_id']}: {item.get('name') or item.get('product')}", 256),
        "url": f"https://nvd.nist.gov/vuln/detail/{item['cve_id']}",
        "description": _cut(f"**{alert['tldr']}**\n\n{alert['technical_summary']}", 4096),
        "color": SEVERITY_COLORS.get(alert.get("severity"), 0x808080),
        "fields": [
            {"name": "Severity", "value": alert.get("severity", "-"), "inline": True},
            {"name": "CVSS", "value": cvss_text, "inline": True},
            {"name": "EPSS", "value": epss_text, "inline": True},
            {"name": "Exploited in the wild", "value": f"Yes (CISA KEV) · Ransomware use: {item.get('known_ransomware_use')}", "inline": False},
            {"name": "CISA due date", "value": item.get("cisa_due_date") or "-", "inline": True},
            {"name": "Affected", "value": _cut(alert.get("affected"), 1024), "inline": False},
            {"name": "Fix", "value": _cut(alert.get("fix"), 1024), "inline": False},
            {"name": "Mitigations", "value": _cut(_bullets(alert.get("mitigations")), 1024), "inline": False},
            {"name": "Detection", "value": _cut(_bullets(alert.get("detection")), 1024), "inline": False},
            {"name": "Gaps in sources", "value": _cut(alert.get("gaps"), 1024), "inline": False},
            {"name": "Sources", "value": _cut(sources, 1024), "inline": False},
        ],
        "footer": {"text": "AI-generated summary. Verify against the vendor advisory."},
    }


def print_alert(item, alert):
    print("\n" + "=" * 70)
    print(f"{item['cve_id']} | {alert.get('severity')} | {item.get('vendor')} {item.get('product')}")
    print("-" * 70)
    print(f"TL;DR: {alert['tldr']}\n")
    print(f"Technical: {alert['technical_summary']}\n")
    print(f"Affected: {alert['affected']}")
    print(f"Fix: {alert['fix']}")
    print(f"Mitigations:\n{_bullets(alert.get('mitigations'))}")
    print(f"Detection:\n{_bullets(alert.get('detection'))}")
    print(f"Gaps: {alert['gaps']}")
    print("=" * 70)


def send_alert(item, alert, webhook_url=None):
    if not webhook_url:
        print_alert(item, alert)
        return

    payload = {"embeds": [build_embed(item, alert)]}
    for _ in range(3):
        r = requests.post(webhook_url, json=payload, timeout=15)
        if r.status_code == 429:  # Discord rate limit
            time.sleep(float(r.json().get("retry_after", 2)))
            continue
        r.raise_for_status()
        print(f"  Sent {item['cve_id']} to Discord")
        time.sleep(1)
        return
    raise RuntimeError("Discord kept rate-limiting the webhook")