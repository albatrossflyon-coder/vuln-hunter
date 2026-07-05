"""Convert triaged findings to SARIF 2.1.0 — the industry-standard static
analysis result format consumed by GitHub Security tab, most CI tooling,
and other scanners. https://sarifweb.azurewebsites.net/
"""

from pathlib import Path
from typing import Any, Dict, List

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# Claude's contextual exploitability rating is the more meaningful signal we
# have (vs. the scanner's generic ERROR/WARNING), so that's what drives level.
EXPLOITABILITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "unknown": "note",
}


def to_sarif(findings: List[Dict[str, Any]], tool_name: str = "vuln-hunter") -> Dict[str, Any]:
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for finding in findings:
        rule_id = finding["rule_id"]
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": finding["message"][:200]},
                "fullDescription": {"text": finding["message"]},
                "properties": {
                    k: v for k, v in {"cwe": finding.get("cwe"), "owasp": finding.get("owasp")}.items()
                    if v
                },
            }

        try:
            uri = Path(finding["path"]).as_posix()
        except (TypeError, ValueError):
            uri = finding["path"]

        results.append({
            "ruleId": rule_id,
            "level": EXPLOITABILITY_TO_LEVEL.get(finding.get("exploitability", "unknown"), "note"),
            "message": {"text": finding.get("explanation") or finding["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": max(finding["start_line"], 1),
                        "endLine": max(finding["end_line"], finding["start_line"], 1),
                    },
                }
            }],
            "properties": {
                "exploitability": finding.get("exploitability"),
                "scanner_severity": finding.get("severity"),
                "suggested_fix": finding.get("suggested_fix"),
            },
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "informationUri": "https://github.com/albatrossflyon-coder/vuln-hunter",
                    "version": "0.1.0",
                    "rules": list(rules_by_id.values()),
                }
            },
            "results": results,
        }],
    }
