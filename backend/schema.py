"""Strawberry GraphQL schema for vuln-hunter.

Scaffold only: types and resolvers are stubbed out. See TODOs for where
this should delegate to the real scan/telemetry data (telemetry.py,
ignore_store.py, all_scanners.py) instead of returning stub values.
"""

import strawberry


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
        # TODO: look up the repo by name via telemetry.py / a real repo store.
        return None

    @strawberry.field
    def query_scan(self, id: strawberry.ID) -> Scan | None:
        # TODO: fetch the scan by id via telemetry.py (scan records live there).
        return None

    @strawberry.field
    def findings_for_scan(self, scan_id: strawberry.ID) -> list[Finding]:
        # TODO: list findings for the scan via telemetry.py / stored scan results.
        return []


schema = strawberry.Schema(query=Query)
