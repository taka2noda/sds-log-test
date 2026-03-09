#!/usr/bin/env python3
"""
Add custom SDS rules from sds_custom_rules.json to a scanning group.

Usage:
  export DD_API_KEY="..."
  export DD_APPLICATION_KEY="..."
  python3 create_custom_rules.py --group-id <group-id>

Options:
  --group-id   Target scanning group ID (required)
  --rules-file Path to rules JSON file (default: sds_custom_rules.json)
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

API_KEY = os.environ.get("DD_API_KEY", "")
APP_KEY = os.environ.get("DD_APPLICATION_KEY", "")


def api(method, path, body=None):
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        f"https://api.datadoghq.com{path}",
        data=data,
        method=method,
        headers={
            "DD-API-KEY": API_KEY,
            "DD-APPLICATION-KEY": APP_KEY,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        print(f"ERROR {e.code}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)


def get_version():
    return api("GET", "/api/v2/sensitive-data-scanner/config")["meta"]["version"]


def create_rule(rule, group_id, version):
    attributes = {
        "name": rule["name"],
        "description": rule.get("description", ""),
        "priority": rule.get("priority", 1),
        "is_enabled": rule.get("is_enabled", True),
        "tags": rule.get("tags", []),
        "text_replacement": rule.get("text_replacement", {"type": "none"}),
        "namespaces": rule.get("namespaces", []),
        "excluded_namespaces": rule.get("excluded_namespaces", []),
        "included_keyword_configuration": rule.get(
            "included_keyword_configuration", {"keywords": [], "character_count": 30}
        ),
    }
    # Custom pattern rule
    if "pattern" in rule:
        attributes["pattern"] = rule["pattern"]

    relationships = {
        "group": {"data": {"id": group_id, "type": "sensitive_data_scanner_group"}}
    }
    # Standard library rule
    if "standard_pattern_id" in rule:
        relationships["standard_pattern"] = {
            "data": {"id": rule["standard_pattern_id"], "type": "sensitive_data_scanner_standard_pattern"}
        }

    return api("POST", "/api/v2/sensitive-data-scanner/config/rules", {
        "meta": {"version": version},
        "data": {
            "type": "sensitive_data_scanner_rule",
            "attributes": attributes,
            "relationships": relationships,
        },
    })


def main():
    if not API_KEY or not APP_KEY:
        print("ERROR: DD_API_KEY and DD_APPLICATION_KEY must be set.", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Add SDS rules to a scanning group")
    parser.add_argument("--group-id", required=True, help="Target scanning group ID")
    parser.add_argument("--rules-file", default="sds_custom_rules.json", help="Rules JSON file")
    args = parser.parse_args()

    rules_path = os.path.join(os.path.dirname(__file__), args.rules_file)
    with open(rules_path) as f:
        config = json.load(f)

    rules = config["rules"]
    print(f"Rules file : {args.rules_file} ({len(rules)} rules)")
    print(f"Group ID   : {args.group_id}")
    print()

    for rule in rules:
        version = get_version()
        resp = create_rule(rule, args.group_id, version)
        rule_id = resp["data"]["id"]
        new_version = resp["meta"]["version"]
        kind = "standard" if "standard_pattern_id" in rule else "custom"
        print(f"  [{kind}] {rule['name']}")
        print(f"          rule_id={rule_id}  version={new_version}")

    print(f"\nAll {len(rules)} rules added successfully.")


if __name__ == "__main__":
    main()
