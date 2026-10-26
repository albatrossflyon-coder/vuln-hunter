"""Manual regression test: SARIF output validates against the real, official
SARIF 2.1.0 JSON schema (fetched live) -- not just structurally eyeballed.
"""

import json
import sys

import jsonschema
import requests

from sarif import to_sarif
from scanner import run_scan

SCHEMA_URL = "https://www.schemastore.org/sarif-2.1.0.json"

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")


def main():
    resp = requests.get(SCHEMA_URL, timeout=30)
    resp.raise_for_status()
    schema = resp.json()

    findings = run_scan("test_sample/vulnerable.py")
    # Fill in placeholder triage fields — schema validation doesn't need real
    # Claude output, just needs the shape to be right.
    for f in findings:
        f.setdefault("explanation", "")
        f.setdefault("exploitability", "unknown")
        f.setdefault("suggested_fix", "")

    sarif_doc = to_sarif(findings)
    jsonschema.validate(instance=sarif_doc, schema=schema)
    print(f"PASS: SARIF output for {len(findings)} finding(s) validates against the official 2.1.0 schema")


if __name__ == "__main__":
    main()
