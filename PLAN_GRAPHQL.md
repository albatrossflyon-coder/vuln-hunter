# GraphQL Resolver Implementation Plan

This plan outlines the concrete implementation steps for the three stubbed GraphQL resolvers in `backend/schema.py`, referencing the actual data structures and functions in `backend/telemetry.py`, `backend/ignore_store.py`, and `backend/all_scanners.py`.

## 1. `query_repo(self, name: str) -> Repo | None`

**Goal:** Retrieve a repository by its name.

*   **Source Data:** `backend/telemetry.py`
*   **Proposed Function(s)/Data Structure(s):**
    *   `telemetry.get_repo_staleness()`: This function returns a list of dictionaries, each containing `repo_path` (which can serve as the repo's name/identifier).
*   **Implementation Steps:**
    1.  Call `telemetry.get_repo_staleness()`.
    2.  Iterate through the returned list of dictionaries.
    3.  Find a dictionary where `repo_path` matches the `name` argument.
    4.  If a match is found, construct a `Repo` object.
*   **Type Mapping:**
    *   `Repo.id`: Map directly from the `repo_path` string (e.g., `strawberry.ID(repo_path)`).
    *   `Repo.name`: Map directly from the `repo_path` string.
*   **Ambiguities:**
    *   The `Repo.id` field is `strawberry.ID`. While `repo_path` can be cast to `strawberry.ID`, it's essentially a string. If a more abstract, persistent ID is ever needed for repos, `repo_path` might not be ideal (though it serves as a unique identifier for now).

## 2. `query_scan(self, id: strawberry.ID) -> Scan | None`

**Goal:** Retrieve a specific scan by its ID.

*   **Source Data:** `backend/telemetry.py`
*   **Proposed Function(s)/Data Structure(s):**
    *   Direct SQL query against the `scans` table using `_connect()` context manager in `telemetry.py`. There is no dedicated `get_scan_by_id` function.
*   **Implementation Steps:**
    1.  Use `telemetry._connect()` to get a database connection.
    2.  Execute a SQL query: `SELECT scan_id, repo_path, status, start_time, end_time, duration_sec, error_reason FROM scans WHERE scan_id = ?` using the provided `id`.
    3.  Fetch the one row result.
    4.  If a row is found, construct a `Scan` object.
*   **Type Mapping:**
    *   `Scan.id`: Map from the `scan_id` column (e.g., `strawberry.ID(row["scan_id"])`).
    *   `Scan.repo_id`: Map from the `repo_path` column (e.g., `strawberry.ID(row["repo_path"])`).
    *   `Scan.status`: Map from the `status` column.
*   **Ambiguities:**
    *   Similar to `Repo.id`, `Scan.repo_id` is `strawberry.ID` but the source (`repo_path`) is a string. `repo_path` will be directly used/cast as `strawberry.ID`.

## 3. `findings_for_scan(self, scan_id: strawberry.ID) -> list[Finding]`

**Goal:** List all findings associated with a given scan ID.

*   **Source Data:** `backend/telemetry.py`, `backend/ignore_store.py`, `backend/all_scanners.py`
*   **Proposed Function(s)/Data Structure(s):**
    *   **AMBIGUITY / MISSING DATA:** The current data model in `telemetry.py` *does not persistently store individual findings* in a retrievable way by `scan_id`. The `scanner_metrics` table stores only *aggregated counts* (total, critical, high, etc.) for each scanner per scan, not the detailed finding objects with `title` and `severity`. `record_scan_results()` in `telemetry.py` receives a list of findings, but this data is used to populate `scanner_metrics` and then discarded; it's not stored for later retrieval of the full finding list.
    *   `backend/all_scanners.py` functions (`run_full_scan`, `run_diff_scan`) *generate* findings, but these are transient and tied to a live scan execution, not stored results.
    *   `backend/ignore_store.py` provides `filter_ignored` and `fingerprint` for processing findings, but it does not *store* the raw findings themselves.
*   **Implementation Steps:**
    *   **Cannot be directly implemented with current persistence model.** To fulfill this resolver, a new data persistence mechanism would be required to store the detailed `List[Dict[str, Any]]` of findings after a scan completes. This could involve:
        *   Storing findings in a new SQLite table, linked by `scan_id`.
        *   Storing findings as JSON within the `scans` table (though this is generally not recommended for large/complex data).
        *   Storing findings in separate files (e.g., JSONL) and referencing them by path from the `scans` table.
*   **Type Mapping:** (Assuming a new findings persistence is implemented)
    *   `Finding.id`: A unique ID for each finding (e.g., `fingerprint` from `ignore_store.py` or a UUID).
    *   `Finding.scan_id`: Map from the input `scan_id`.
    *   `Finding.title`: Map from a `title` or `rule_id` field in the stored finding data.
    *   `Finding.severity`: Map from a `severity` or `exploitability` field in the stored finding data.
*   **Ambiguities:**
    *   **PRIMARY AMBIGUITY:** The absence of a stored list of detailed findings. This resolver, as currently defined by the `Finding` GraphQL type (which expects `id`, `title`, `severity`), cannot be implemented without a change to the underlying data persistence.
    *   If a summary of findings (e.g., counts by severity) is acceptable instead of individual findings, then `telemetry.scanner_metrics` could be queried, but this would not match the `list[Finding]` return type of the resolver.
