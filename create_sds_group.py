#!/usr/bin/env python3
"""
Create a Datadog SDS scanning group.

Usage:
  export DD_API_KEY="..."
  export DD_APPLICATION_KEY="..."
  python3 create_sds_group.py --name "my-group"

Options:
  --name     Group name (required)
  --product  Product to scan: logs | apm (default: logs)
  --disabled Create the group in disabled state
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

API_KEY = os.environ.get("DD_API_KEY", "")
APP_KEY = os.environ.get("DD_APPLICATION_KEY", "")
BASE_URL = "https://api.datadoghq.com/api/v2/sensitive-data-scanner/config"


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


def get_config():
    return api("GET", "/api/v2/sensitive-data-scanner/config")


def main():
    if not API_KEY or not APP_KEY:
        print("ERROR: DD_API_KEY and DD_APPLICATION_KEY must be set.", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Create a Datadog SDS scanning group")
    parser.add_argument("--name", required=True, help="Group name")
    parser.add_argument("--product", default="logs", choices=["logs", "apm"], help="Product to scan")
    parser.add_argument("--disabled", action="store_true", help="Create group in disabled state")
    args = parser.parse_args()

    filter_query = "service:sds-test"

    config = get_config()
    version = config["meta"]["version"]
    config_id = config["data"]["id"]

    print(f"Config ID : {config_id}")
    print(f"Version   : {version}")
    print(f"Creating group '{args.name}' (filter: {filter_query}) ...")

    resp = api("POST", "/api/v2/sensitive-data-scanner/config/groups", {
        "meta": {"version": version},
        "data": {
            "type": "sensitive_data_scanner_group",
            "attributes": {
                "name": args.name,
                "description": "",
                "filter": {"query": filter_query},
                "is_enabled": not args.disabled,
                "product_list": [args.product],
                "samplings": [],
            },
            "relationships": {
                "configuration": {
                    "data": {"id": config_id, "type": "sensitive_data_scanner_configuration"}
                }
            },
        },
    })

    group_id = resp["data"]["id"]
    print(f"Created   : group_id={group_id}")
    print(f"New version: {resp['meta']['version']}")
    print(f"\nNext step:")
    print(f"  python3 create_custom_rules.py --group-id {group_id}")


if __name__ == "__main__":
    main()
