"""Strawberry GraphQL schema for vuln-hunter.

All three resolvers are wired to real data in telemetry.py.
"""

import strawberry

import telemetry


@strawberry.type
class Repo:
    id: strawberry.ID
    name: str


@strawberry.type
class Scan:
    id: strawberry.ID
    repo_id: strawberry.ID
    status: str


@strawberry.type
class Finding:
    id: strawberry.ID
    scan_id: strawberry.ID
    title: str
    severity: str


@strawberry.type
class Query:
    @strawberry.field
    def query_repo(self, name: str) -> Repo | None:
        # There's no dedicated repo table -- repo_path (as recorded on scans)
        # is the only identifier telemetry.py has, so it doubles as both id
        # and name here.
        for row in telemetry.get_repo_staleness():
            if row["repo_path"] == name:
                return Repo(id=strawberry.ID(row["repo_path"]), name=row["repo_path"])
        return None

    @strawberry.field
    def query_scan(self, id: strawberry.ID) -> Scan | None:
        with telemetry._connect() as conn:
            row = conn.execute(
                "SELECT scan_id, repo_path, status FROM scans WHERE scan_id = ?",
                (str(id),),
            ).fetchone()
        if row is None:
            return None
        return Scan(
            id=strawberry.ID(row["scan_id"]),
            repo_id=strawberry.ID(row["repo_path"]),
            status=row["status"],
        )

    @strawberry.field
    def findings_for_scan(self, scan_id: strawberry.ID) -> list[Finding]:
        findings = telemetry.get_findings_by_scan_id(str(scan_id))
        result = []
        for f in findings:
            # title/severity precedence: message/severity are triage-enriched
            # fields and preferred when present, falling back to the raw
            # scanner-level rule_id/exploitability (see PLAN_GRAPHQL_PHASE2.md).
            title = f.get("message") or f.get("rule_id") or ""
            severity = f.get("severity") or f.get("exploitability") or ""
            result.append(
                Finding(
                    id=strawberry.ID(f["finding_id"]),
                    scan_id=scan_id,
                    title=title,
                    severity=severity,
                )
            )
        return result


schema = strawberry.Schema(query=Query)
