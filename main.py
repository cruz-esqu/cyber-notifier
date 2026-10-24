"""Cyber notifier v0: new CISA KEV entries -> enrich -> AI alert -> Discord."""
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from ingest import enrich, fetch_kev
from notify import send_alert
from summarize import make_client, summarize

STATE_FILE = Path(__file__).parent / "state.json"
FIRST_RUN_SAMPLE = 3  # on the very first run, alert on only the 3 newest entries


def load_seen():
    if not STATE_FILE.exists():
        return None
    return set(json.loads(STATE_FILE.read_text()))


def save_seen(seen):
    STATE_FILE.write_text(json.dumps(sorted(seen)))


def main():
    load_dotenv()
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        sys.exit("Missing GEMINI_API_KEY in your .env file")

    model = os.getenv("MODEL") or "gemini-3.6-flash"
    max_per_run = int(os.getenv("MAX_PER_RUN") or "5")
    nvd_key = os.getenv("NVD_API_KEY") or None
    webhook = os.getenv("DISCORD_WEBHOOK_URL") or None

    print("Fetching CISA KEV catalog...")
    kev = fetch_kev()
    print(f"  {len(kev)} entries in catalog")

    seen = load_seen()
    if seen is None:
        seen = {v["cveID"] for v in kev[FIRST_RUN_SAMPLE:]}
        save_seen(seen)
        print(f"First run: skipping {len(seen)} older entries, "
              f"alerting on the {FIRST_RUN_SAMPLE} newest.")

    new = [v for v in kev if v["cveID"] not in seen][:max_per_run]
    if not new:
        print("No new KEV entries since last run.")
        return

    client = make_client(api_key)
    for v in new:
        cve = v["cveID"]
        print(f"Processing {cve} ({v.get('vendorProject')} {v.get('product')})...")
        try:
            item = enrich(v, nvd_key)
            alert = summarize(item, client, model)
            send_alert(item, alert, webhook)
        except Exception as e:  # keep going if one CVE fails
            print(f"  Failed on {cve}: {e}")
            continue
        seen.add(cve)
        save_seen(seen)

    print("Done.")


if __name__ == "__main__":
    main()