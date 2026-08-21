"use client";

import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001";
const POLL_MS = 3000;

type Summary = {
  window_hours: number;
  total_scans: number;
  completed: number;
  hung: number;
  crashed: number;
  success_rate: number;
  p50_duration_sec: number;
  p90_duration_sec: number;
  p90_near_timeout: boolean;
  scanner_volumes: Record<string, number>;
  silent_zero_scanners: string[];
  severity_breakdown: { critical: number; high: number; medium: number; low: number };
  fp_rate: number;
  stopper_bugs_count: number;
  mcp_process_count: number;
};

type RepoStaleness = {
  repo_path: string;
  last_success_ago_sec: number | null;
  last_status: string;
};

type ActiveScan = {
  scan_id: string;
  repo_path: string;
  tool: string;
  elapsed_sec: number;
  progress_step: number;
  progress_total: number;
  current_scanner: string | null;
};

type EventLog = {
  event_id: number;
  scan_id: string | null;
  event_type: string;
  component: string;
  message: string;
  stack_trace: string | null;
  timestamp: number;
};

// Validated palette (dataviz skill reference instance) -- dark chart surface only,
// this is an ops-center dashboard meant to look like one regardless of OS theme.
const COLOR = {
  surface: "#1a1a19",
  page: "#0d0d0d",
  ink: "#ffffff",
  inkSecondary: "#c3c2b7",
  inkMuted: "#898781",
  grid: "#2c2c2a",
  good: "#0ca30c",
  warning: "#fab219",
  serious: "#ec835a",
  critical: "#e66767",
  seqBlue: "#3987e5",
  // categorical, fixed order -- one slot per scanner, never cycled
  scanner: { semgrep: "#3987e5", gitleaks: "#d95926", "pip-audit": "#199e70", trivy: "#c98500" } as Record<string, string>,
};

function fmtAgo(sec: number | null): string {
  if (sec === null) return "never";
  if (sec < 3600) return `${Math.round(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.round(sec / 3600)}h ago`;
  return `${Math.round(sec / 86400)}d ago`;
}

function StatTile({ label, value, sub, tone }: { label: string; value: string; sub: string; tone?: "good" | "warning" | "critical" }) {
  const toneColor = tone ? COLOR[tone] : COLOR.ink;
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
      }}
    >
      <div style={{ fontSize: 11, letterSpacing: 0.6, textTransform: "uppercase", color: COLOR.inkMuted }}>{label}</div>
      <motion.div
        key={value}
        initial={{ opacity: 0.4, scale: 0.97 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.25 }}
        style={{ fontSize: 30, fontWeight: 700, color: toneColor, margin: "4px 0 2px", fontVariantNumeric: "tabular-nums" }}
      >
        {value}
      </motion.div>
      <div style={{ fontSize: 12, color: COLOR.inkSecondary }}>{sub}</div>
    </motion.div>
  );
}

function ScannerBarChart({ volumes }: { volumes: Record<string, number> }) {
  const entries = Object.entries(volumes);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  return (
    <div>
      {entries.map(([name, count]) => (
        <div key={name} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
          <div style={{ width: 78, fontSize: 12, color: COLOR.inkSecondary, textAlign: "right" }}>{name}</div>
          <div style={{ flex: 1, background: COLOR.page, borderRadius: 4, height: 14, position: "relative" }}>
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${(count / max) * 100}%` }}
              transition={{ duration: 0.4, ease: "easeOut" }}
              style={{
                height: "100%",
                borderRadius: 4,
                background: COLOR.scanner[name] ?? COLOR.inkMuted,
              }}
            />
          </div>
          <div style={{ width: 28, fontSize: 12, color: COLOR.ink, fontVariantNumeric: "tabular-nums" }}>{count}</div>
        </div>
      ))}
      {entries.length === 0 && <div style={{ fontSize: 12, color: COLOR.inkMuted }}>No scans in this window.</div>}
    </div>
  );
}

function RadialGauge({
  value,
  max,
  displayValue,
  label,
  sub,
  color,
}: {
  value: number;
  max: number;
  displayValue: string;
  label: string;
  sub: string;
  color: string;
}) {
  const pct = Math.max(0, Math.min(1, value / max));
  // 270-degree sweep gauge (a full circle reads as a pie/clock, not a meter).
  const sweep = 270;
  const r = 58;
  const circumference = 2 * Math.PI * r * (sweep / 360);
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      style={{
        background: COLOR.surface,
        border: `1px solid ${color === COLOR.inkMuted ? COLOR.grid : color}55`,
        borderRadius: 10,
        padding: "16px 18px",
        boxShadow: `0 1px 0 rgba(255,255,255,0.03) inset, 0 10px 28px rgba(0,0,0,0.4), 0 6px 24px ${color === COLOR.inkMuted ? "transparent" : color + "40"}`,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        width: 190,
      }}
    >
      <div style={{ fontSize: 11, letterSpacing: 0.6, textTransform: "uppercase", color: COLOR.inkMuted, alignSelf: "flex-start" }}>{label}</div>
      <svg width={150} height={132} viewBox="0 0 130 130" style={{ marginTop: 4 }}>
        <g transform="rotate(135 65 65)">
          <circle cx={65} cy={65} r={r} fill="none" stroke={COLOR.grid} strokeWidth={11} strokeDasharray={`${circumference} ${2 * Math.PI * r}`} strokeLinecap="round" />
          <motion.circle
            cx={65}
            cy={65}
            r={r}
            fill="none"
            stroke={color}
            strokeWidth={11}
            strokeLinecap="round"
            strokeDasharray={`${circumference} ${2 * Math.PI * r}`}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: circumference * (1 - pct) }}
            transition={{ duration: 0.6, ease: "easeOut" }}
          />
        </g>
        <text x={65} y={73} textAnchor="middle" fontSize={26} fontWeight={700} fill={color} style={{ fontVariantNumeric: "tabular-nums" }}>
          {displayValue}
        </text>
      </svg>
      <div style={{ fontSize: 12, color: COLOR.inkSecondary, textAlign: "center", marginTop: -6 }}>{sub}</div>
    </motion.div>
  );
}

function SeverityBar({ sev }: { sev: Summary["severity_breakdown"] }) {
  const total = sev.critical + sev.high + sev.medium + sev.low;
  const segs: [string, number, string][] = [
    ["critical", sev.critical, COLOR.critical],
    ["high", sev.high, COLOR.serious],
    ["medium", sev.medium, COLOR.warning],
    ["low", sev.low, COLOR.good],
  ];
  return (
    <div>
      <div style={{ display: "flex", height: 16, borderRadius: 4, overflow: "hidden", gap: 2, background: COLOR.page }}>
        {segs.map(([name, count, color]) =>
          count > 0 ? (
            <motion.div
              key={name}
              initial={{ flexGrow: 0 }}
              animate={{ flexGrow: count }}
              transition={{ duration: 0.4 }}
              style={{ background: color, flexBasis: 0 }}
              title={`${name}: ${count}`}
            />
          ) : null
        )}
        {total === 0 && <div style={{ flex: 1, background: COLOR.grid }} />}
      </div>
      <div style={{ display: "flex", gap: 14, marginTop: 8, flexWrap: "wrap" }}>
        {segs.map(([name, count, color]) => (
          <div key={name} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: COLOR.inkSecondary }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: color, display: "inline-block" }} />
            {name}: {count}
          </div>
        ))}
      </div>
    </div>
  );
}

type ScanUrlFinding = { severity: string };
type ScanUrlResult = { total: number; ignored_count: number; findings: ScanUrlFinding[] };

function ScanUrlBox() {
  const [url, setUrl] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState<"idle" | "scanning" | "done" | "error">("idle");
  const [elapsed, setElapsed] = useState(0);
  const [result, setResult] = useState<ScanUrlResult | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (status !== "scanning") return;
    const start = Date.now();
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - start) / 1000)), 1000);
    return () => clearInterval(id);
  }, [status]);

  async function runScan() {
    if (!url.trim() || status === "scanning") return;
    setStatus("scanning");
    setElapsed(0);
    setResult(null);
    setError("");
    try {
      // Same-origin Next.js route, not the Fly.io backend directly -- it holds
      // the real API key server-side and checks the password, so nothing
      // secret ever reaches this browser tab.
      const res = await fetch("/api/scan-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim(), password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "scan failed");
      setResult(data);
      setStatus("done");
    } catch (e) {
      setError(e instanceof Error ? e.message : "scan failed");
      setStatus("error");
    }
  }

  const sevCount = (sev: string) => result?.findings.filter((f) => f.severity.toLowerCase() === sev).length ?? 0;

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
      <div style={{ fontSize: 11, letterSpacing: 0.6, textTransform: "uppercase", color: COLOR.inkMuted }}>Scan a repo</div>
      <div style={{ display: "flex", gap: 8 }}>
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && runScan()}
          placeholder="https://github.com/owner/repo"
          disabled={status === "scanning"}
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
        <input
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && runScan()}
          placeholder="password"
          type="password"
          disabled={status === "scanning"}
          style={{
            width: 100,
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
          onClick={runScan}
          disabled={status === "scanning" || !url.trim()}
          style={{
            background: status === "scanning" ? COLOR.grid : COLOR.seqBlue,
            border: "none",
            borderRadius: 6,
            padding: "0 16px",
            color: COLOR.ink,
            fontSize: 13,
            fontWeight: 600,
            cursor: status === "scanning" || !url.trim() ? "default" : "pointer",
          }}
        >
          Scan
        </button>
      </div>
      <div style={{ fontFamily: "monospace", fontSize: 12, minHeight: 18 }}>
        {status === "idle" && <span style={{ color: COLOR.inkMuted }}>Clones the repo and runs semgrep / gitleaks / pip-audit / trivy against it, live.</span>}
        {status === "scanning" && (
          <motion.span animate={{ opacity: [1, 0.4, 1] }} transition={{ duration: 1.2, repeat: Infinity }} style={{ color: COLOR.seqBlue }}>
            &gt; scanning… {elapsed}s elapsed
          </motion.span>
        )}
        {status === "error" && <span style={{ color: COLOR.critical }}>&gt; {error}</span>}
        {status === "done" && result && (
          <span style={{ color: COLOR.ink }}>
            &gt; {result.total} finding(s) in {elapsed}s —{" "}
            <span style={{ color: COLOR.critical }}>{sevCount("critical")} crit</span>,{" "}
            <span style={{ color: COLOR.serious }}>{sevCount("high")} high</span>,{" "}
            <span style={{ color: COLOR.warning }}>{sevCount("medium")} med</span>,{" "}
            <span style={{ color: COLOR.good }}>{sevCount("low")} low</span>
          </span>
        )}
      </div>
    </motion.div>
  );
}

type ScanDetails = {
  id: string;
  repoId: string;
  status: string;
};

type GraphQLFinding = {
  id: string;
  title: string;
  severity: string;
};

type GraphQLResult = {
  data?: {
    queryScan: ScanDetails | null;
    findingsForScan: GraphQLFinding[];
  };
  errors?: any[];
};

function ScanDetailsPanel() {
  const [scanIdInput, setScanIdInput] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [scanDetails, setScanDetails] = useState<ScanDetails | null>(null);
  const [findings, setFindings] = useState<GraphQLFinding[]>([]);
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
                repoId
                status
              }
              findingsForScan(scanId: $scanId) {
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
        Lookup scan by ID
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
            <span style={{ color: COLOR.ink }}>Repo: {scanDetails.repoId}, Status: {scanDetails.status}</span>
            {findings.length > 0 ? (
              <span style={{ color: COLOR.ink }}>
                <br />Total Findings: {findings.length} —{" "}
                <span style={{ color: COLOR.critical }}>{sevCount("critical")} crit</span>,{" "}
                <span style={{ color: COLOR.serious }}>{sevCount("high")} high</span>,{" "}
                <span style={{ color: COLOR.warning }}>{sevCount("medium")} med</span>,{" "}
                <span style={{ color: COLOR.good }}>{sevCount("low")} low</span>
              </span>
            ) : (
              <span style={{ color: COLOR.inkMuted }}><br />No findings found for this scan.</span>
            )}
          </div>
        ) : status === "done" && !scanDetails ? (
          <span style={{ color: COLOR.inkMuted }}>&gt; Scan ID not found.</span>
        ) : null}
      </div>
    </motion.div>
  );
}

function ActiveScanBar({ scan }: { scan: ActiveScan }) {
  const pct = scan.progress_total > 0 ? Math.round((scan.progress_step / scan.progress_total) * 100) : 0;
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      style={{
        background: COLOR.surface,
        border: `1px solid ${COLOR.seqBlue}55`,
        borderRadius: 10,
        padding: "12px 16px",
        marginBottom: 8,
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 6 }}>
        <span style={{ fontFamily: "monospace", color: COLOR.inkSecondary }}>{scan.repo_path}</span>
        <span style={{ color: COLOR.inkMuted }}>
          {scan.current_scanner ? `${scan.current_scanner}…` : "starting…"} ({scan.progress_step}/{scan.progress_total || "?"}) — {Math.round(scan.elapsed_sec)}s
        </span>
      </div>
      <div style={{ background: COLOR.page, borderRadius: 4, height: 8, overflow: "hidden" }}>
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.4, ease: "easeOut" }}
          style={{ height: "100%", background: COLOR.seqBlue }}
        />
      </div>
    </motion.div>
  );
}

export default function Dashboard() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [repos, setRepos] = useState<RepoStaleness[]>([]);
  const [events, setEvents] = useState<EventLog[]>([]);
  const [activeScans, setActiveScans] = useState<ActiveScan[]>([]);
  const [connError, setConnError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function poll() {
      try {
        const [s, r, e, a] = await Promise.all([
          fetch(`${API_URL}/telemetry/summary`).then((res) => res.json()),
          fetch(`${API_URL}/telemetry/repos`).then((res) => res.json()),
          fetch(`${API_URL}/telemetry/events?limit=25`).then((res) => res.json()),
          fetch(`${API_URL}/telemetry/active`).then((res) => res.json()),
        ]);
        if (!cancelled) {
          setSummary(s);
          setRepos(r);
          setEvents(e);
          setActiveScans(a);
          setConnError(false);
        }
      } catch {
        if (!cancelled) setConnError(true);
      }
    }
    poll();
    const id = setInterval(poll, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const successTone = summary ? (summary.success_rate >= 95 ? "good" : summary.success_rate >= 80 ? "warning" : "critical") : undefined;
  const durationTone = summary?.p90_near_timeout ? "warning" : "good";
  const mcpTone = summary ? (summary.mcp_process_count > 1 ? "warning" : "good") : undefined;
  const fpTone = summary ? (summary.fp_rate <= 5 ? "good" : summary.fp_rate <= 15 ? "warning" : "critical") : undefined;
  const toneColor = { good: COLOR.good, warning: COLOR.warning, critical: COLOR.critical } as const;

  return (
    <div style={{ minHeight: "100vh", background: COLOR.page, color: COLOR.ink, fontFamily: "system-ui, -apple-system, 'Segoe UI', sans-serif" }}>
      <div style={{ maxWidth: 1100, margin: "0 auto", padding: "28px 20px 60px" }}>
        <header className="header-row" style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 22 }}>
          <div>
            <h1 style={{ fontSize: 30, fontWeight: 800, letterSpacing: "-0.02em", margin: 0, textTransform: "uppercase" }}>
              Vuln Hunter <span style={{ color: COLOR.seqBlue }}>Operations Center</span>
            </h1>
            <p style={{ fontSize: 12, color: COLOR.inkMuted, margin: "6px 0 0", display: "flex", alignItems: "center", gap: 6 }}>
              <motion.span
                animate={{ opacity: [1, 0.3, 1] }}
                transition={{ duration: 1.6, repeat: Infinity }}
                style={{ width: 6, height: 6, borderRadius: "50%", background: connError ? COLOR.critical : COLOR.good, display: "inline-block" }}
              />
              Live scan telemetry — last {summary?.window_hours ?? 24}h
            </p>
          </div>
          {connError && (
            <span style={{ fontSize: 12, color: COLOR.critical, border: `1px solid ${COLOR.critical}`, borderRadius: 6, padding: "3px 9px" }}>
              backend unreachable
            </span>
          )}
        </header>

        {activeScans.length > 0 && (
          <div style={{ marginBottom: 12 }}>
            <AnimatePresence initial={false}>
              {activeScans.map((s) => (
                <ActiveScanBar key={s.scan_id} scan={s} />
              ))}
            </AnimatePresence>
          </div>
        )}

        <div className="gauge-row" style={{ display: "flex", flexWrap: "wrap", gap: 12, marginBottom: 12, alignItems: "stretch" }}>
          <RadialGauge
            label="Success rate"
            value={summary?.success_rate ?? 0}
            max={100}
            displayValue={summary ? `${summary.success_rate}%` : "--"}
            sub={summary ? `${summary.completed} ok / ${summary.hung} hung / ${summary.crashed} crashed` : ""}
            color={successTone ? toneColor[successTone] : COLOR.inkMuted}
          />
          <ScanUrlBox />
          <ScanDetailsPanel />
          <RadialGauge
            label="False-positive rate"
            value={summary?.fp_rate ?? 0}
            max={100}
            displayValue={summary ? `${summary.fp_rate}%` : "--"}
            sub={summary && summary.silent_zero_scanners.length > 0 ? `silent-zero: ${summary.silent_zero_scanners.join(", ")}` : "no silent-zero scanners"}
            color={fpTone ? toneColor[fpTone] : COLOR.inkMuted}
          />
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12, marginBottom: 20 }}>
          <StatTile
            label="Total scans"
            value={summary ? String(summary.total_scans) : "--"}
            sub={`last ${summary?.window_hours ?? 24}h`}
          />
          <StatTile
            label="Duration p50 / p90"
            value={summary ? `${summary.p50_duration_sec}s / ${summary.p90_duration_sec}s` : "--"}
            sub={summary?.p90_near_timeout ? "p90 near 30min timeout" : "within budget"}
            tone={durationTone}
          />
          <StatTile
            label="MCP processes"
            value={summary ? String(summary.mcp_process_count) : "--"}
            sub={summary ? `${summary.stopper_bugs_count} stopper bug(s)` : ""}
            tone={mcpTone}
          />
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
          <div style={{ background: COLOR.surface, border: `1px solid ${COLOR.grid}`, borderRadius: 10, padding: 16 }}>
            <div style={{ fontSize: 11, letterSpacing: 0.6, textTransform: "uppercase", color: COLOR.inkMuted, marginBottom: 10 }}>
              Findings by scanner
            </div>
            {summary && <ScannerBarChart volumes={summary.scanner_volumes} />}
          </div>
          <div style={{ background: COLOR.surface, border: `1px solid ${COLOR.grid}`, borderRadius: 10, padding: 16 }}>
            <div style={{ fontSize: 11, letterSpacing: 0.6, textTransform: "uppercase", color: COLOR.inkMuted, marginBottom: 10 }}>
              Severity breakdown
            </div>
            {summary && <SeverityBar sev={summary.severity_breakdown} />}
          </div>
        </div>

        <div style={{ background: COLOR.surface, border: `1px solid ${COLOR.grid}`, borderRadius: 10, padding: 16, marginBottom: 12 }}>
          <div style={{ fontSize: 11, letterSpacing: 0.6, textTransform: "uppercase", color: COLOR.inkMuted, marginBottom: 10 }}>
            Repo staleness
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ color: COLOR.inkMuted, textAlign: "left" }}>
                <th style={{ fontWeight: 500, paddingBottom: 6 }}>Repo</th>
                <th style={{ fontWeight: 500, paddingBottom: 6 }}>Last success</th>
                <th style={{ fontWeight: 500, paddingBottom: 6 }}>Last status</th>
              </tr>
            </thead>
            <tbody>
              {repos.map((r) => (
                <tr key={r.repo_path} style={{ borderTop: `1px solid ${COLOR.grid}` }}>
                  <td style={{ padding: "6px 0", color: COLOR.inkSecondary, fontFamily: "monospace", fontSize: 12 }}>{r.repo_path}</td>
                  <td style={{ padding: "6px 0" }}>{fmtAgo(r.last_success_ago_sec)}</td>
                  <td style={{ padding: "6px 0" }}>
                    <span
                      style={{
                        color:
                          r.last_status === "COMPLETED" ? COLOR.good : r.last_status === "HUNG" ? COLOR.warning : r.last_status === "CRASHED" ? COLOR.critical : COLOR.inkMuted,
                      }}
                    >
                      {r.last_status}
                    </span>
                  </td>
                </tr>
              ))}
              {repos.length === 0 && (
                <tr>
                  <td colSpan={3} style={{ padding: "10px 0", color: COLOR.inkMuted }}>
                    No scans recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div style={{ background: COLOR.surface, border: `1px solid ${COLOR.grid}`, borderRadius: 10, padding: 16 }}>
          <div style={{ fontSize: 11, letterSpacing: 0.6, textTransform: "uppercase", color: COLOR.inkMuted, marginBottom: 10 }}>
            Live event &amp; bug log
          </div>
          <div style={{ maxHeight: 360, overflowY: "auto", fontFamily: "monospace", fontSize: 12 }}>
            <AnimatePresence initial={false}>
              {events.map((ev) => (
                <motion.div
                  key={ev.event_id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  style={{ padding: "6px 0", borderBottom: `1px solid ${COLOR.grid}` }}
                >
                  <span
                    style={{
                      color: ev.event_type === "STOPPER_BUG" ? COLOR.critical : ev.event_type === "ERROR" || ev.event_type === "WARN" ? COLOR.warning : COLOR.inkSecondary,
                      fontWeight: 700,
                      marginRight: 8,
                    }}
                  >
                    [{ev.event_type}]
                  </span>
                  <span style={{ color: COLOR.ink }}>{ev.component}:</span> <span style={{ color: COLOR.inkSecondary }}>{ev.message}</span>
                  {ev.stack_trace && (
                    <pre style={{ margin: "4px 0 0", padding: 8, background: COLOR.page, borderRadius: 6, color: COLOR.inkMuted, whiteSpace: "pre-wrap", fontSize: 11 }}>
                      {ev.stack_trace}
                    </pre>
                  )}
                </motion.div>
              ))}
              {events.length === 0 && <div style={{ color: COLOR.inkMuted, padding: "8px 0" }}>No events yet.</div>}
            </AnimatePresence>
          </div>
        </div>
      </div>
      <style jsx>{`
        @media (max-width: 640px) {
          .header-row {
            flex-direction: column;
            align-items: center;
            text-align: center;
          }
          .gauge-row {
            justify-content: center;
          }
        }
      `}</style>
    </div>
  );
}
