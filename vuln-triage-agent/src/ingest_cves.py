"""
CVE Ingestion Module
Fetches recent CVE data from the NVD (National Vulnerability Database) API
and saves it locally as JSON for downstream processing.

NVD API docs: https://nvd.nist.gov/developers/vulnerabilities
No API key required for low-volume use (rate limit: 5 requests / 30 sec).
"""

import requests
import json
import time
from datetime import datetime, timedelta
from pathlib import Path

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DATA_DIR = Path(__file__).parent.parent / "data"


def fetch_recent_cves(days_back: int = 7, results_per_page: int = 50) -> list[dict]:
    """
    Fetch CVEs published in the last `days_back` days.

    Returns a list of simplified CVE dicts containing the fields
    most relevant for triage: id, description, severity, CVSS score,
    published date, and affected products (CPE matches).
    """
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": results_per_page,
    }

    print(f"Fetching CVEs published between {start_date.date()} and {end_date.date()}...")
    response = requests.get(NVD_API_URL, params=params, timeout=30)
    response.raise_for_status()
    raw = response.json()

    cves = []
    for item in raw.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id")

        # Description (English)
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )

        # CVSS metrics (prefer v3.1, fall back to v3.0, then v2)
        metrics = cve_data.get("metrics", {})
        cvss_score = None
        severity = None
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
                break

        # Affected products (CPE URIs) - first few only
        affected = []
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        affected.append(cpe_match.get("criteria"))
        affected = affected[:5]  # cap for readability

        cves.append({
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "published": cve_data.get("published"),
            "affected_products": affected,
        })

    return cves


def save_cves(cves: list[dict], filename: str = "cves_raw.json"):
    DATA_DIR.mkdir(exist_ok=True)
    out_path = DATA_DIR / filename
    with open(out_path, "w") as f:
        json.dump(cves, f, indent=2)
    print(f"Saved {len(cves)} CVEs to {out_path}")


if __name__ == "__main__":
    cves = fetch_recent_cves(days_back=7)
    save_cves(cves)

    # Print a quick summary
    severities = {}
    for c in cves:
        sev = c["severity"] or "UNKNOWN"
        severities[sev] = severities.get(sev, 0) + 1
    print("\nSeverity breakdown:")
    for sev, count in sorted(severities.items()):
        print(f"  {sev}: {count}")
