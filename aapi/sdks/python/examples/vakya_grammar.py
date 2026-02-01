"""VĀKYA Grammar Examples (Python)

This example demonstrates what a VĀKYA looks like as a *grammar* (7-slot envelope)
when used as an agent instruction.

Run:
  PYTHONPATH=sdks/python AAPI_GATEWAY_URL=http://127.0.0.1:9000 python3 sdks/python/examples/vakya_grammar.py

Notes:
- We keep resources inside the file adapter sandbox: /tmp/aapi
- This file focuses on showing the structure (Kartā/Karma/Kriyā/...) clearly.
"""

import os
import json
from datetime import datetime, timezone

from aapi import (
    AapiClient,
    Vakya,
    Karta,
    Karma,
    Kriya,
    Adhikarana,
)

GATEWAY_URL = os.getenv("AAPI_GATEWAY_URL", "http://127.0.0.1:9000")


def print_vakya(v: Vakya, title: str) -> None:
    print(f"\n===== {title} =====")
    print(json.dumps(v.model_dump(exclude_none=True, mode="json"), indent=2))


def example_file_write_explicit_vakya() -> Vakya:
    """A VĀKYA constructed explicitly (not via builder).

    Grammar mapping:
    - V1 Kartā: who is acting
    - V2 Karma: what is acted upon
    - V3 Kriyā: the action
    - V7 Adhikaraṇa: under what authority (capability/ttl)
    - body: action params
    """
    return Vakya(
        v1_karta=Karta(
            pid="agent:python-example",
            actor_type="agent",
        ),
        v2_karma=Karma(
            rid="file:/tmp/aapi/grammar_demo.txt",
            kind="file",
            labels={"project": "aapi", "usecase": "vakya_grammar"},
        ),
        v3_kriya=Kriya(
            action="file.write",
            expected_effect="UPDATE",
            idempotent=False,
        ),
        v7_adhikarana=Adhikarana(
            cap={"cap_ref": "cap:default"},
        ),
        body={
            "content": "Hello from explicit VĀKYA grammar example!\n",
        },
    )


def example_file_read_explicit_vakya() -> Vakya:
    return Vakya(
        v1_karta=Karta(
            pid="agent:python-example",
            actor_type="agent",
        ),
        v2_karma=Karma(
            rid="file:/tmp/aapi/grammar_demo.txt",
            kind="file",
        ),
        v3_kriya=Kriya(
            action="file.read",
            expected_effect="READ",
            idempotent=True,
        ),
        v7_adhikarana=Adhikarana(
            cap={"cap_ref": "cap:default"},
        ),
        body={
            "path": "/tmp/aapi/grammar_demo.txt",
        },
    )


def example_http_get_explicit_vakya() -> Vakya:
    """HTTP example.

    NOTE: Depending on your network/policy configuration, http requests may be allowed/blocked.
    """
    return Vakya(
        v1_karta=Karta(
            pid="agent:python-example",
            actor_type="agent",
        ),
        v2_karma=Karma(
            rid="https://example.com",
            kind="http",
        ),
        v3_kriya=Kriya(
            action="http.get",
            expected_effect="READ",
            idempotent=True,
        ),
        v7_adhikarana=Adhikarana(
            cap={"cap_ref": "cap:default"},
        ),
        body={
            "headers": {"accept": "text/html"},
        },
    )


def main() -> None:
    client = AapiClient(base_url=GATEWAY_URL)

    # 1) Explicit VĀKYA: file.write
    v_write = example_file_write_explicit_vakya()
    print_vakya(v_write, "VĀKYA (Explicit) - file.write")
    resp_write = client.submit(v_write)
    print("\nGateway Response (file.write):")
    print(json.dumps(resp_write, indent=2))

    # 2) Explicit VĀKYA: file.read
    v_read = example_file_read_explicit_vakya()
    print_vakya(v_read, "VĀKYA (Explicit) - file.read")
    resp_read = client.submit(v_read)
    print("\nGateway Response (file.read):")
    print(json.dumps(resp_read, indent=2))

    # 3) Explicit VĀKYA: http.get
    v_http = example_http_get_explicit_vakya()
    print_vakya(v_http, "VĀKYA (Explicit) - http.get")
    resp_http = client.submit(v_http)
    print("\nGateway Response (http.get):")
    print(json.dumps(resp_http, indent=2))

    client.close()


if __name__ == "__main__":
    main()
