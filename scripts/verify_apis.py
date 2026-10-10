"""
verify_apis.py — One-time API capability verification for Panoptes.

Runs the V1-V7 checks from Day 1 §Verification Action Items.
Read-only. No scanning. Safe to re-run (respects rate limits).

Usage:
    python scripts/verify_apis.py

Output:
    - Console report
    - scripts/verification_report.json
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = REPO_ROOT / "scripts" / "verification_report.json"

TEST_IP = "8.8.8.8"        # Google DNS: stable, well documented
TEST_IP_ALT = "1.1.1.1"    # Cloudflare DNS: second IP for the rate-limit test
TIMEOUT = 10               # seconds

load_dotenv(REPO_ROOT / ".env")
SHODAN_KEY = os.getenv("SHODAN_API_KEY")
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")

results = []


def now():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def record(test_id, name, passed, status, detail, fields=None, response=None):
    """Store a result and print it."""
    entry = {
        "test_id": test_id,
        "name": name,
        "passed": passed,
        "status_code": status,
        "detail": detail,
        "sample_fields": fields or [],
        "timestamp": now(),
    }
    if response is not None and not passed:
        entry["raw_preview"] = response.text[:500]  # for debugging failures
    results.append(entry)
    print(f"  [{'OK' if passed else 'FAIL'}] {test_id}: {name} — {detail}")


def get(test_id, name, url, **kwargs):
    """GET a URL. On a network error, record a failure and return None."""
    try:
        return requests.get(url, timeout=TIMEOUT, **kwargs)
    except requests.RequestException as e:
        record(test_id, name, False, None, f"Request failed: {e}")
        return None


def key_missing(test_id, name, key, env_var):
    """Record a failure and return True if the key isn't set."""
    if key:
        return False
    record(test_id, name, False, None, f"{env_var} not set — skipping")
    return True


def unexpected(test_id, name, r, expected="Unexpected status"):
    record(test_id, name, False, r.status_code, f"{expected}, got {r.status_code}", response=r)


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def v1_shodan_host():
    tid, name = "V1", "Shodan /shodan/host/{ip}"
    if key_missing(tid, name, SHODAN_KEY, "SHODAN_API_KEY"):
        return
    r = get(tid, name, f"https://api.shodan.io/shodan/host/{TEST_IP}",
            params={"key": SHODAN_KEY})
    if r is None:
        return
    if r.status_code == 200:
        fields = sorted(r.json())
        record(tid, name, True, 200, f"Returned {len(fields)} top-level fields", fields[:15])
    else:
        unexpected(tid, name, r)


def v2_shodan_internetdb():
    tid, name = "V2", "Shodan InternetDB (no auth)"
    r = get(tid, name, f"https://internetdb.shodan.io/{TEST_IP}")
    if r is None:
        return
    if r.status_code == 200:
        fields = sorted(r.json())
        record(tid, name, True, 200, f"Returned fields: {', '.join(fields)}", fields)
    elif r.status_code == 404:
        record(tid, name, True, 404, "No data for this IP (valid empty result)")
    else:
        unexpected(tid, name, r)


def v3_shodan_rate_limit():
    tid, name = "V3", "Shodan rate limit (1 req/sec)"
    if key_missing(tid, name, SHODAN_KEY, "SHODAN_API_KEY"):
        return
    params = {"key": SHODAN_KEY}
    # Two back-to-back calls: the second should be rate limited.
    if get(tid, name, f"https://api.shodan.io/shodan/host/{TEST_IP}", params=params) is None:
        return
    r = get(tid, name, f"https://api.shodan.io/shodan/host/{TEST_IP_ALT}", params=params)
    if r is None:
        return
    if r.status_code == 429:
        record(tid, name, True, 429, "Second immediate call correctly returned 429")
    else:
        unexpected(tid, name, r, "Expected 429")


def v4_v5_virustotal():
    """V4 (IP lookup) and V5 (no premium fields) share one request to save rate limit."""
    v4 = ("V4", "VirusTotal /api/v3/ip_addresses/{ip}")
    v5 = ("V5", "VT free tier excludes port/vuln data")
    if key_missing(*v4, VT_KEY, "VIRUSTOTAL_API_KEY"):
        key_missing(*v5, VT_KEY, "VIRUSTOTAL_API_KEY")
        return

    r = get(*v4, f"https://www.virustotal.com/api/v3/ip_addresses/{TEST_IP}",
            headers={"x-apikey": VT_KEY})
    if r is None:
        return
    if r.status_code != 200:
        unexpected(*v4, r)
        record(*v5, False, r.status_code, "Could not fetch VT data to inspect")
        return

    attrs = r.json().get("data", {}).get("attributes", {})
    fields = sorted(attrs)
    record(*v4, True, 200, f"Returned {len(fields)} attribute fields", fields[:20])

    premium = [f for f in ("port_info", "vulnerabilities") if f in attrs]
    if premium:
        record(*v5, False, 200, f"Unexpected premium fields present: {premium}")
    else:
        record(*v5, True, 200, "Confirmed: no port_info or vulnerabilities fields present")


def v6_ipinfo_lite():
    tid, name = "V6", "IPinfo Lite /lite/{ip}"
    if key_missing(tid, name, IPINFO_TOKEN, "IPINFO_TOKEN"):
        return
    r = get(tid, name, f"https://api.ipinfo.io/lite/{TEST_IP}", params={"token": IPINFO_TOKEN})
    if r is None:
        return
    if r.status_code == 200:
        fields = sorted(r.json())
        record(tid, name, True, 200, f"Returned fields: {', '.join(fields)}", fields)
    else:
        unexpected(tid, name, r)


def v7_ipinfo_invalid_token():
    tid, name = "V7", "IPinfo invalid token error shape"
    r = get(tid, name, f"https://api.ipinfo.io/lite/{TEST_IP}",
            params={"token": "invalid_token_for_testing"})
    if r is None:
        return
    if r.status_code in (401, 403, 406):
        record(tid, name, True, r.status_code, f"Correctly rejected with {r.status_code}")
    else:
        unexpected(tid, name, r, "Expected 401/403/406")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# (title, function, seconds to wait afterwards to respect rate limits)
CHECKS = [
    ("V1 — Shodan host lookup", v1_shodan_host, 1.1),            # Shodan: 1 req/sec
    ("V2 — Shodan InternetDB (no auth)", v2_shodan_internetdb, 1.1),
    ("V3 — Shodan rate limit (1 req/sec)", v3_shodan_rate_limit, 0),
    ("V4/V5 — VirusTotal lookup + free-tier fields", v4_v5_virustotal, 0),
    ("V6 — IPinfo Lite lookup", v6_ipinfo_lite, 0),
    ("V7 — IPinfo invalid token error shape", v7_ipinfo_invalid_token, 0),
]


def heading(title):
    print(f"\n{'=' * 72}\n  {title}\n{'=' * 72}")


def main():
    heading("Panoptes — API Capability Verification")
    print(f"  Test IP:        {TEST_IP}")
    print(f"  Timestamp:      {now()}")
    for label, key in [("Shodan key", SHODAN_KEY), ("VT key", VT_KEY), ("IPinfo token", IPINFO_TOKEN)]:
        print(f"  {label + ':':<15} {'set' if key else 'MISSING'}")

    for title, check, delay in CHECKS:
        heading(title)
        check()
        time.sleep(delay)

    heading("Summary")
    passed = sum(r["passed"] for r in results)
    print(f"  Passed: {passed}/{len(results)}\n")
    for r in results:
        print(f"  [{'PASS' if r['passed'] else 'FAIL'}] {r['test_id']}: {r['name']}")
        print(f"         {r['detail']}")

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(
        {"generated_at": now(), "test_ip": TEST_IP, "results": results}, indent=2))
    print(f"\n  Report saved to: {REPORT_PATH.relative_to(REPO_ROOT)}")

    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())