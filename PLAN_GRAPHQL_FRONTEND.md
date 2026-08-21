# GraphQL Frontend Integration Plan

This plan outlines the integration of a new GraphQL-powered panel into the `vuln-hunter` dashboard, demonstrating the ability to query related data (scan details and its findings) in a single request. It will use a server-side proxy to keep the `SCAN_API_KEY` secure.

## 1. GraphQL Query String

The panel will execute a single GraphQL query to fetch a scan's details and its associated findings based on a provided `scan_id`. This query leverages GraphQL's ability to fetch multiple related resources in one round trip.

```graphql
query GetScanDetailsAndFindings($scanId: ID!) {
  queryScan(id: $scanId) {
    id
    repo_id
    status
  }
  findingsForScan(scan_id: $scanId) {
    id
    title
    severity
  }
}
```

*   **Variables:** The query expects one variable: `scanId` of type `ID!`, which will be the user-inputted scan ID.
*   **`queryScan` fields:** Fetches the `id`, `repo_id`, and `status` of the requested scan.
*   **`findingsForScan` fields:** Fetches the `id`, `title`, and `severity` for all findings related to that scan.

## 2. New Proxy Route: `frontend/app/api/graphql/route.ts`

A new Next.js API route will be created to proxy GraphQL requests from the frontend to the `vuln-hunter` backend. This ensures that the `SCAN_API_KEY` remains on the server and is never exposed to the client browser, following the existing pattern of `frontend/app/api/scan-url/route.ts`.

**File Path:** `frontend/app/api/graphql/route.ts`

**Contents:**

```typescript
import { NextRequest, NextResponse } from "next/server";

// Server-side proxy for GraphQL requests to the vuln-hunter backend.
// This route injects the SCAN_API_KEY from environment variables to keep it
// off the browser.
export async function POST(req: NextRequest) {
  const { query, variables } = await req.json();

  const backendUrl = process.env.BACKEND_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001";
  const apiKey = process.env.SCAN_API_KEY;

  try {
    const res = await fetch(`${backendUrl}/graphql`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(apiKey ? { "X-API-Key": apiKey } : {}),
      },
      body: JSON.stringify({ query, variables }),
    });

    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch (error) {
    console.error("GraphQL proxy error:", error);
    return NextResponse.json(
      { error: "Failed to fetch GraphQL data", details: error instanceof Error ? error.message : String(error) },
      { status: 500 }
    );
  }
}
```

**Justification:**
*   **`POST` method:** Standard for GraphQL queries.
*   **Request body:** Expects `query` (the GraphQL query string) and `variables` (an object of query variables).
*   **`backendUrl` and `apiKey`:** Retrieved from environment variables, matching `scan-url/route.ts`.
*   **Headers:** Sets `Content-Type: application/json` and includes `X-API-Key` if available.
*   **Error Handling:** Catches network or parsing errors and returns a 500 status with details.

## 3. New Panel Component: `ScanDetailsPanel` in `frontend/app/dashboard/page.tsx`

A new React component, `ScanDetailsPanel`, will be added to `frontend/app/dashboard/page.tsx`. It will provide an input field for a scan ID and display the retrieved scan details and findings summary in a style consistent with existing dashboard elements like `ScanUrlBox`.

**Component Name:** `ScanDetailsPanel`

**Styling and Placement:**
*   The component will adopt the visual style of `StatTile` and `ScanUrlBox`:
    ```css
    background: COLOR.surface,
    border: `1px solid ${COLOR.grid}`,
    borderRadius: 10,
    padding: "16px 18px",
    boxShadow: "0 1px 0 rgba(255,255,255,0.03) inset, 0 8px 24px rgba(0,0,0,0.35)",
    flex: "1 1 260px", /* To fit flexibly in the gauge-row or similar flex container */
    display: "flex",
    flexDirection: "column",
    gap: 10,
    ```
*   It will be placed in `dashboard/page.tsx` within the `<div className="gauge-row">` alongside the `ScanUrlBox` to maintain the existing flexible grid layout. The `gauge-row` div already uses `display: "flex", flexWrap: "wrap", gap: 12`, which is suitable.

**`ScanDetailsPanel` Component Structure (Conceptual):**

```tsx
// In frontend/app/dashboard/page.tsx, after the existing imports and types

type ScanDetails = {
  id: string;
  repo_id: string;
  status: string;
};

type Finding = {
  id: string;
  title: string;
  severity: string;
};

type GraphQLResult = {
  data?: {
    queryScan: ScanDetails | null;
    findingsForScan: Finding[];
  };
  errors?: any[];
};

function ScanDetailsPanel() {
  const [scanIdInput, setScanIdInput] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [scanDetails, setScanDetails] = useState<ScanDetails | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState("");

  async function fetchScanDetails() {
    if (!scanIdInput.trim() || status === "loading") return;
    setStatus("loading");
    setScanDetails(null);
    setFindings([]);
    setError("");

    try {
      const res = await fetch("/api/graphql", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query: `
            query GetScanDetailsAndFindings($scanId: ID!) {
              queryScan(id: $scanId) {
                id
                repo_id
                status
              }
              findingsForScan(scan_id: $scanId) {
                id
                title
                severity
              }
            }
          `,
          variables: { scanId: scanIdInput.trim() },
        }),
      });

      const result: GraphQLResult = await res.json();

      if (!res.ok || result.errors) {
        throw new Error(result.errors?.[0]?.message || "GraphQL query failed");
      }

      setScanDetails(result.data?.queryScan || null);
      setFindings(result.data?.findingsForScan || []);
      setStatus("done");

    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch scan details");
      setStatus("error");
    }
  }

  const sevCount = (sev: string) => findings.filter((f) => f.severity.toLowerCase() === sev).length;

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      style={{
        background: COLOR.surface,
        border: `1px solid ${COLOR.grid}`,
        borderRadius: 10,
        padding: "16px 18px",
        boxShadow: "0 1px 0 rgba(255,255,255,0.03) inset, 0 8px 24px rgba(0,0,0,0.35)",
        flex: "1 1 260px",
        display: "flex",
        flexDirection: "column",
        gap: 10,
      }}
    >
      <div style={{ fontSize: 11, letterSpacing: 0.6, textTransform: "uppercase", color: COLOR.inkMuted }}>
        Lookup Scan by ID
      </div>
      <div style={{ display: "flex", gap: 8 }}>
        <input
          value={scanIdInput}
          onChange={(e) => setScanIdInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && fetchScanDetails()}
          placeholder="Enter Scan ID (e.g., scan-abcdef)"
          disabled={status === "loading"}
          style={{
            flex: 1,
            background: COLOR.page,
            border: `1px solid ${COLOR.grid}`,
            borderRadius: 6,
            padding: "8px 10px",
            color: COLOR.ink,
            fontSize: 13,
            fontFamily: "monospace",
          }}
        />
        <button
          onClick={fetchScanDetails}
          disabled={status === "loading" || !scanIdInput.trim()}
          style={{
            background: status === "loading" ? COLOR.grid : COLOR.seqBlue,
            border: "none",
            borderRadius: 6,
            padding: "0 16px",
            color: COLOR.ink,
            fontSize: 13,
            fontWeight: 600,
            cursor: status === "loading" || !scanIdInput.trim() ? "default" : "pointer",
          }}
        >
          Lookup
        </button>
      </div>

      <div style={{ fontFamily: "monospace", fontSize: 12, minHeight: 18 }}>
        {status === "idle" && <span style={{ color: COLOR.inkMuted }}>Enter a scan ID to view its details and findings.</span>}
        {status === "loading" && (
          <motion.span animate={{ opacity: [1, 0.4, 1] }} transition={{ duration: 1.2, repeat: Infinity }} style={{ color: COLOR.seqBlue }}>
            &gt; fetching…
          </motion.span>
        )}
        {status === "error" && <span style={{ color: COLOR.critical }}>&gt; {error}</span>}
        {status === "done" && scanDetails ? (
          <div>
            <span style={{ color: COLOR.ink }}>Repo: {scanDetails.repo_id}, Status: {scanDetails.status}</span>
            {findings.length > 0 ? (
              <span style={{ color: COLOR.ink }}>
                <br/>Total Findings: {findings.length} —{" "}
                <span style={{ color: COLOR.critical }}>{sevCount("critical")} crit</span>,{" "}
                <span style={{ color: COLOR.serious }}>{sevCount("high")} high</span>,{" "}
                <span style={{ color: COLOR.warning }}>{sevCount("medium")} med</span>,{" "}
                <span style={{ color: COLOR.good }}>{sevCount("low")} low</span>
              </span>
            ) : (
              <span style={{ color: COLOR.inkMuted }}><br/>No findings found for this scan.</span>
            )}
          </div>
        ) : status === "done" && !scanDetails ? (
          <span style={{ color: COLOR.inkMuted }}>&gt; Scan ID not found.</span>
        ) : null}
      </div>
    </motion.div>
  );
}

// ... within the Dashboard component's return statement, inside the gauge-row div
// Find this existing line:
// <ScanUrlBox />
// And add ScanDetailsPanel next to it:
// <ScanUrlBox />
// <ScanDetailsPanel />
```

**Justification:**
*   **State Management:** `useState` hooks manage the input, loading state, and the fetched `scanDetails` and `findings`.
*   **Fetch Logic:** Makes a `POST` request to the new `/api/graphql` proxy route, passing the GraphQL query and variables. Handles loading, success, and error states.
*   **Styling Consistency:** Reuses `COLOR` constants and mimics the visual layout of `ScanUrlBox` for inputs, buttons, and status messages.
*   **Result Display:** Shows basic scan details and a breakdown of findings by severity, similar to how `ScanUrlBox` summarizes its results, using `COLOR.critical`, `COLOR.serious`, etc., for severity counts. Handles cases where no scan or no findings are returned.

## 4. Integration into `dashboard/page.tsx`

The `ScanDetailsPanel` component will be included in the `Dashboard` component's `return` statement. It should be placed within the same `gauge-row` div that contains `ScanUrlBox` to ensure it integrates seamlessly with the existing layout and responsive behavior.

**Location in `Dashboard` component:**

```tsx
// ... inside the <div className="gauge-row"> around line 488
        <div className="gauge-row" style={{ display: "flex", flexWrap: "wrap", gap: 12, marginBottom: 12, alignItems: "stretch" }}>
          <RadialGauge
            label="Success rate"
            // ... existing RadialGauge props
          />
          <ScanUrlBox />
          {/* Add the new ScanDetailsPanel here */}
          <ScanDetailsPanel /> 
          <RadialGauge
            label="False-positive rate"
            // ... existing RadialGauge props
          />
        </div>
// ... rest of the dashboard components
```

This placement maintains the flexible row layout, allowing the `ScanDetailsPanel` to resize and wrap appropriately on different screen sizes, consistent with `ScanUrlBox` and `RadialGauge` components. The required `type` definitions (`ScanDetails`, `Finding`, `GraphQLResult`) will be added near the other type definitions at the top of `dashboard/page.tsx`.