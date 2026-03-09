#!/usr/bin/env python3
"""
指定したSDS スキャニンググループ内のライブラリルールの
キーワード一致条件をすべて空にするスクリプト。

【使い方】
  export DD_API_KEY="..."
  export DD_APPLICATION_KEY="..."
  python3 clear_rule_keywords.py <group-name>

【例】
  python3 clear_rule_keywords.py sds-test
"""
import json
import os
import sys
import urllib.request

# API キー（環境変数から取得）
API_KEY = os.environ["DD_API_KEY"]
APP_KEY = os.environ["DD_APPLICATION_KEY"]

GROUP_NAME = sys.argv[1]


def api(method, path, body=None):
    req = urllib.request.Request(
        f"https://api.datadoghq.com{path}",
        data=json.dumps(body).encode() if body else None,
        method=method,
        headers={
            "DD-API-KEY": API_KEY,
            "DD-APPLICATION-KEY": APP_KEY,
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req) as r:
        return json.load(r)


# SDS 設定を取得
config = api("GET", "/api/v2/sensitive-data-scanner/config")
included = config["included"]

# 対象グループのルール ID を取得
group = next(i for i in included
             if i.get("type") == "sensitive_data_scanner_group"
             and i["attributes"]["name"] == GROUP_NAME)
rule_ids = {r["id"] for r in group["relationships"]["rules"]["data"]}

# ライブラリルール（standard_pattern あり）だけ抽出して、"keywords"を [] (空欄)に設定
library_rules = [
    i for i in included
    if i.get("type") == "sensitive_data_scanner_rule"
    and i["id"] in rule_ids
    and i.get("relationships", {}).get("standard_pattern", {}).get("data")
]

print(f"グループ: {GROUP_NAME}")
print(f"ライブラリルール数: {len(library_rules)}\n")

for rule in library_rules:
    a = rule["attributes"]
    version = api("GET", "/api/v2/sensitive-data-scanner/config")["meta"]["version"]

    api("PATCH", f"/api/v2/sensitive-data-scanner/config/rules/{rule['id']}", {
        "meta": {"version": version},
        "data": {
            "id":   rule["id"],
            "type": "sensitive_data_scanner_rule",
            "attributes": {
                "name":              a["name"],
                "description":       a.get("description", ""),
                "is_enabled":        a["is_enabled"],
                "priority":          a.get("priority", 1),
                "tags":              a.get("tags", []),
                "text_replacement":  a.get("text_replacement", {"type": "none"}),
                "namespaces":        a.get("namespaces", []),
                "excluded_namespaces": a.get("excluded_namespaces", []),
                "included_keyword_configuration": {
                    "keywords": [],
                    "character_count": a.get("included_keyword_configuration", {}).get("character_count", 30),
                },
            },
        },
    })
    print(f"  削除完了: {a['name']}")

print(f"\n完了: {len(library_rules)} 件のライブラリルールのキーワードを空にしました。")
