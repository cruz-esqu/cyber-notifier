"""Pull vulnerability data from public sources: CISA KEV, NVD, and EPSS."""
import time

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
HEADERS = {"User-Agent": "cyber-notifier/0.1"}


def fetch_kev():
    """Return the CISA KEV catalog, newest additions first."""
    r = requests.get(KEV_URL, headers=HEADERS, timeout=30)
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities", [])
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    return vulns


def fetch_nvd(cve_id, api_key=None):
    """Return description, CVSS, and reference links for a CVE from NVD."""
    headers = dict(HEADERS)
    if api_key:
        headers["apiKey"] = api_key
    try:
        r = requests.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=30)
        r.raise_for_status()
        items = r.json().get("vulnerabilities", [])
    except requests.RequestException as e:
        print(f"  NVD lookup failed for {cve_id}: {e}")
        return {}
    if not items:
        return {}

    cve = items[0]["cve"]
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )

    cvss = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            cvss = {
                "version": data.get("version"),
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity"),
                "vector": data.get("vectorString"),
            }
            break

    references = [ref["url"] for ref in cve.get("references", []) if ref.get("url")][:15]
    return {"description": description, "cvss": cvss, "references": references}


def fetch_epss(cve_id):
    """Return the EPSS exploit-probability score for a CVE, or None."""
    try:
        r = requests.get(EPSS_URL, params={"cve": cve_id}, headers=HEADERS, timeout=15)
        r.raise_for_status()
        data = r.json().get("data", [])
    except requests.RequestException:
        return None
    if not data:
        return None
    return {"score": float(data[0]["epss"]), "percentile": float(data[0]["percentile"])}


def enrich(kev_item, nvd_api_key=None):
    """Combine a KEV entry with NVD and EPSS data into one record."""
    cve_id = kev_item["cveID"]
    nvd = fetch_nvd(cve_id, nvd_api_key)
    epss = fetch_epss(cve_id)

    # KEV "notes" holds vendor advisory links separated by " ; "
    kev_links = [
        part.strip()
        for part in kev_item.get("notes", "").split(";")
        if part.strip().startswith("http")
    ]

    # NVD allows ~5 requests per 30s without a key, ~50 with one
    time.sleep(0.7 if nvd_api_key else 6)

    return {
        "cve_id": cve_id,
        "vendor": kev_item.get("vendorProject"),
        "product": kev_item.get("product"),
        "name": kev_item.get("vulnerabilityName"),
        "kev_description": kev_item.get("shortDescription"),
        "cisa_required_action": kev_item.get("requiredAction"),
        "date_added_to_kev": kev_item.get("dateAdded"),
        "cisa_due_date": kev_item.get("dueDate"),
        "known_ransomware_use": kev_item.get("knownRansomwareCampaignUse"),
        "cwes": kev_item.get("cwes", []),
        "nvd_description": nvd.get("description"),
        "cvss": nvd.get("cvss"),
        "epss": epss,
        "references": kev_links + [u for u in nvd.get("references", []) if u not in kev_links],
    }