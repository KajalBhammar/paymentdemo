"""
Checks whether the Cybersource credentials in .env are valid for the
TEST host (apitest.cybersource.com) or the PRODUCTION host
(api.cybersource.com), or both.

Safe to run: it only requests a capture context (a signed session
token). It does not submit a card, complete a payment, or move money.

Usage:
    python check_key_environment.py
"""

import os
import json
import hmac
import base64
import hashlib

from datetime import datetime, timezone
from email.utils import format_datetime

import requests

from dotenv import load_dotenv


load_dotenv()


MERCHANT_ID = os.getenv("CYBERSOURCE_MERCHANT_ID")
API_KEY = os.getenv("CYBERSOURCE_API_KEY")
SHARED_SECRET = os.getenv("CYBERSOURCE_SHARED_SECRET")

RESOURCE = "/up/v1/capture-contexts"

TARGET_ORIGIN = "https://underling-gab-document.ngrok-free.dev"


def build_headers(host, body):

    digest = "SHA-256=" + base64.b64encode(
        hashlib.sha256(body.encode("utf-8")).digest()
    ).decode("utf-8")

    date = format_datetime(datetime.now(timezone.utc), usegmt=True)

    signature_string = (
        f"host: {host}\n"
        f"v-c-date: {date}\n"
        f"request-target: post {RESOURCE}\n"
        f"digest: {digest}\n"
        f"v-c-merchant-id: {MERCHANT_ID}"
    )

    secret = base64.b64decode(SHARED_SECRET)

    signature = base64.b64encode(
        hmac.new(secret, signature_string.encode("utf-8"), hashlib.sha256).digest()
    ).decode("utf-8")

    signature_header = (
        f'keyid="{API_KEY}",'
        f'algorithm="HmacSHA256",'
        f'headers="host v-c-date request-target digest v-c-merchant-id",'
        f'signature="{signature}"'
    )

    return {
        "Content-Type": "application/json",
        "Accept": "application/jwt",
        "Host": host,
        "v-c-date": date,
        "v-c-merchant-id": MERCHANT_ID,
        "Digest": digest,
        "Signature": signature_header,
    }


def test_host(host):

    payload = {
        "targetOrigins": [TARGET_ORIGIN],
        "clientVersion": "0.31",
        "country": "US",
        "locale": "en_US",
        "allowedPaymentTypes": ["PANENTRY"],
        "data": {
            "orderInformation": {
                "amountDetails": {
                    "totalAmount": "1.00",
                    "currency": "USD",
                }
            }
        },
    }

    body = json.dumps(payload, separators=(",", ":"))
    headers = build_headers(host, body)
    url = f"https://{host}{RESOURCE}"

    try:
        response = requests.post(url, headers=headers, data=body, timeout=15)
    except requests.RequestException as exc:
        return None, str(exc)

    return response.status_code, response.text[:300]


def main():

    if not MERCHANT_ID or not API_KEY or not SHARED_SECRET:
        raise SystemExit(
            "CYBERSOURCE_MERCHANT_ID / CYBERSOURCE_API_KEY / "
            "CYBERSOURCE_SHARED_SECRET missing from .env"
        )

    print(f"Merchant ID : {MERCHANT_ID}")
    print(f"API Key     : {API_KEY}")
    print()

    for label, host in (
        ("TEST       (apitest.cybersource.com)", "apitest.cybersource.com"),
        ("PRODUCTION (api.cybersource.com)     ", "api.cybersource.com"),
    ):
        status, detail = test_host(host)

        if status in (200, 201):
            verdict = "VALID for this host"
        elif status in (401, 403):
            verdict = "REJECTED — key/secret not valid on this host"
        elif status is None:
            verdict = f"Could not connect ({detail})"
        else:
            verdict = f"Unexpected response ({status})"

        print(f"{label}: HTTP {status} -> {verdict}")

        if status not in (200, 201):
            print(f"    {detail}")

        print()


if __name__ == "__main__":
    main()
