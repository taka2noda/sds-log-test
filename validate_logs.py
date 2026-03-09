#!/usr/bin/env python3
"""
Validate that SDS correctly masked sensitive data in recent Datadog logs.

Usage:
  export DD_API_KEY="..."
  export DD_APPLICATION_KEY="..."
  python3 validate_logs.py

Options:
  --service   Service name to query (default: sds-test)
  --source    Log source to filter on (default: sds-log-test)
  --since     How far back to search, e.g. now-10m (default: now-5m)
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

API_KEY = os.environ.get("DD_API_KEY", "")
APP_KEY = os.environ.get("DD_APPLICATION_KEY", "")

# Raw sensitive patterns that must NOT appear in any log after SDS processing
RAW_PATTERNS = [
    (r"高橋|渡辺|伊藤",              "JP kanji name"),
    (r"たかはし|わたなべ|みさき",    "JP hiragana name"),
    (r"イトウ|サクラ",               "JP katakana name"),
    (r"092-000-0000|050-0000-0000|045-000-0000", "JP phone number"),
    (r"\b450-0002\b|\b600-8216\b|\b060-0001\b",  "JP postal code"),
    (r"愛知県|京都府|北海道",         "JP prefecture (address)"),
    (r"371449635398431|6011111111111117|378282246310005", "Credit card PAN"),
    (r"(?<![=\[])(?:cvv|securityCode)=\"\d{3,4}\"", "Raw CVV value"),
    (r"hanako\.suzuki@example|jiro\.sato@example",   "Email address"),
]

# Masked tokens that MUST appear in specific logs (request_id → expected tokens)
EXPECTED_MASKS = {
    "a9cfab7b8df2": ["[jp_kanji]", "[jp_hiragana_kana]", "[jp_phone_number]", "[jp_postal_code]", "[jp_address]"],
    "7bde7f85cc58": ["[jp_kanji]", "[jp_hiragana_kana]", "[jp_phone_number]", "[jp_postal_code]", "[jp_address]"],
    "2c5445707fbc": ["[jp_kanji]", "[jp_hiragana_kana]", "[jp_postal_code]", "[jp_address]",
                     "[jp_phone_number]", "[card_number]", "[cvv]"],
    "d51ea40d9869": ["[card_number]", "[cvv]"],
    "e91a1da24fe5": ["[card_number]", "[cvv]"],
    "dbef589724fe": ["[card_number]"],
}


def fetch_logs(service, source, since):
    payload = json.dumps({
        "filter": {
            "query": f"service:{service} source:{source}",
            "from": since,
            "to": "now",
        },
        "sort": "timestamp",
        "page": {"limit": 25},
    }).encode()
    req = urllib.request.Request(
        "https://api.datadoghq.com/api/v2/logs/events/search",
        data=payload,
        method="POST",
        headers={
            "DD-API-KEY": API_KEY,
            "DD-APPLICATION-KEY": APP_KEY,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as r:
            return json.load(r).get("data", [])
    except urllib.error.HTTPError as e:
        print(f"ERROR {e.code}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)


def validate(logs):
    results = []
    passed = 0
    failed = 0

    for log in logs:
        msg = log["attributes"]["message"]
        parts = msg.split()
        request_id = next((p.split("=")[1] for p in parts if p.startswith("request_id=")), None)

        log_pass = True
        issues = []

        # Check no raw sensitive data remains
        for pattern, label in RAW_PATTERNS:
            if re.search(pattern, msg):
                issues.append(f"FAIL  raw data found: {label}")
                log_pass = False

        # Check expected mask tokens are present
        if request_id and request_id in EXPECTED_MASKS:
            for token in EXPECTED_MASKS[request_id]:
                if token not in msg:
                    issues.append(f"FAIL  expected token missing: {token}")
                    log_pass = False

        if log_pass:
            passed += 1
        else:
            failed += 1

        results.append((request_id or "unknown", log_pass, issues, msg))

    return results, passed, failed


def main():
    if not API_KEY or not APP_KEY:
        print("ERROR: DD_API_KEY and DD_APPLICATION_KEY must be set.", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Validate SDS masking in Datadog logs")
    parser.add_argument("--service", default="sds-test")
    parser.add_argument("--source", default="sds-test")
    parser.add_argument("--since", default="now-5m")
    args = parser.parse_args()

    print(f"Fetching logs: service={args.service} source={args.source} since={args.since}\n")
    logs = fetch_logs(args.service, args.source, args.since)

    if not logs:
        print("No logs found. Try --since now-30m or re-run send_logs.py first.")
        sys.exit(1)

    # Deduplicate: keep only the latest log per request_id
    seen = {}
    for log in logs:
        msg = log["attributes"]["message"]
        parts = msg.split()
        rid = next((p.split("=")[1] for p in parts if p.startswith("request_id=")), log["id"])
        seen[rid] = log
    deduped = list(seen.values())
    if len(logs) != len(deduped):
        print(f"Found {len(logs)} log(s), deduplicated to {len(deduped)} (latest per request_id). Validating...\n")
    else:
        print(f"Found {len(deduped)} log(s). Validating...\n")
    results, passed, failed = validate(deduped)

    for request_id, ok, issues, msg in results:
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] request_id={request_id}")
        print(f"       {msg[:120]}{'...' if len(msg) > 120 else ''}")
        for issue in issues:
            print(f"       {issue}")
        print()

    print("-" * 50)
    print(f"Result: {passed} passed, {failed} failed out of {len(results)} logs")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
