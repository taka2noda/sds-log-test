#!/usr/bin/env python3
import json
import urllib.request
import os

API_KEY = os.environ.get("DD_API_KEY", "")
if not API_KEY:
    raise ValueError("DD_API_KEY environment variable is not set")

ENDPOINT = "https://http-intake.logs.datadoghq.com/api/v2/logs"

logs = [
    {
        "ddsource": "sds-test",
        "ddtags": "env:dev",
        "hostname": "tw0vlap003",
        "service": "sds-test",
        "status": "warn",
        "message": '2026-03-02T13:48:58+09:00 host=tw0vlap003 service=sds-test env=dev request_id=a9cfab7b8df2 level=WARN msg="raw request body" endpoint="/chargeback" body="{\\\"name\\\":\\\"高橋 美咲\\\",\\\"furigana\\\":\\\"たかはし みさき\\\",\\\"tel\\\":\\\"092-000-0000\\\",\\\"zip\\\":\\\"450-0002\\\",\\\"addr\\\":\\\"愛知県名古屋市中村区名駅1-1-1\\\"}"',
    },
    {
        "ddsource": "sds-test",
        "ddtags": "env:dev",
        "hostname": "tw0vlap003",
        "service": "sds-test",
        "status": "error",
        "message": "2026-03-02T13:48:53+09:00 host=tw0vlap003 service=sds-test env=dev request_id=7bde7f85cc58 level=ERROR msg=\"sql error\" endpoint=\"/customer/update\" sql=\"INSERT INTO customer(name_kj,name_kn,tel,zip,addr,email) VALUES('渡辺 健','わたなべ けん','050-0000-0000','600-8216','京都府京都市下京区烏丸通七条下る1-1','jiro.sato@example.org');\" error=\"duplicate key\"",
    },
    {
        "ddsource": "sds-test",
        "ddtags": "env:dev",
        "hostname": "tw0vlap003",
        "service": "sds-test",
        "status": "info",
        "message": '2026-03-02T13:48:44+09:00 host=tw0vlap003 service=sds-test env=dev request_id=2c5445707fbc level=INFO msg="checkout payload" endpoint="/gateway/callback" order_id="ORD000037" customer_name="伊藤 さくら" customer_kana="イトウ サクラ" postal_code="060-0001" address="北海道札幌市中央区北1条西1-1" phone="045-000-0000" email="hanako.suzuki@example.net" cardNumber="371449635398431" expiry="02/28" securityCode="369"',
    },
    {
        "ddsource": "sds-test",
        "ddtags": "env:dev",
        "hostname": "tw0vlap003",
        "service": "sds-test",
        "status": "warn",
        "message": '2026-03-02T13:48:20+09:00 host=tw0vlap003 service=sds-test env=dev request_id=d51ea40d9869 level=WARN msg="bind variables logged" endpoint="/gateway/callback" sql="UPDATE payments SET amount=:1 WHERE order_id=:2" binds=":1=2587.49,:2=ORD000013" pan="371449635398431" exp="02/29" cvv="481"',
    },
    {
        "ddsource": "sds-test",
        "ddtags": "env:dev",
        "hostname": "tw0vlap003",
        "service": "sds-test",
        "status": "error",
        "message": '2026-03-02T13:48:45+09:00 host=tw0vlap003 service=sds-test env=dev request_id=e91a1da24fe5 level=ERROR msg="gateway timeout" endpoint="/customer/update" txn_id="TXN00000646" pan="6011111111111117" exp_date="03/29" cvv="406" track2="6011111111111117=29031234567890" merchant="KOBE-SHOP"',
    },
    {
        "ddsource": "sds-test",
        "ddtags": "env:dev",
        "hostname": "tw0vlap003",
        "service": "sds-test",
        "status": "error",
        "message": "2026-03-02T13:48:19+09:00 host=tw0vlap003 service=sds-test env=dev request_id=dbef589724fe level=ERROR msg=\"payment insert failed\" endpoint=\"/tokenize\" sql=\"INSERT INTO payments(order_id,pan,exp,cvv,amount) VALUES('ORD000012','378282246310005','01/28','444','2388.76');\" error=\"invalid field\"",
    },
]

payload = json.dumps(logs).encode("utf-8")
req = urllib.request.Request(
    ENDPOINT,
    data=payload,
    headers={
        "Content-Type": "application/json",
        "DD-API-KEY": API_KEY,
    },
    method="POST",
)

with urllib.request.urlopen(req) as resp:
    print(f"Status: {resp.status}")
    print(f"Response: {resp.read().decode()}")
    print(f"\n{len(logs)} logs sent successfully.")
