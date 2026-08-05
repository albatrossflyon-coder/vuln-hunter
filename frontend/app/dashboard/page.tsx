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

export default function Dashboard() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [repos, setRepos] = useState<RepoStaleness[]>([]);
  const [events, setEvents] = useState<EventLog[]>([]);
  const [connError, setConnError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function poll() {
      try {
        const [s, r, e] = await Promise.all([
          fetch(`${API_URL}/telemetry/summary`).then((res) => res.json()),
          fetch(`${API_URL}/telemetry/repos`).then((res) => res.json()),
          fetch(`${API_URL}/telemetry/events?limit=25`).then((res) => res.json()),
        ]);
        if (!cancelled) {
          setSummary(s);
          setRepos(r);
          setEvents(e);
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

  return (
    <div style={{ minHeight: "100vh", background: COLOR.page, color: COLOR.ink, fontFamily: "system-ui, -apple-system, 'Segoe UI', sans-serif" }}>
      <div style={{ maxWidth: 1100, margin: "0 auto", padding: "28px 20px 60px" }}>
        <header style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 22 }}>
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>Vuln Hunter Operations Center</h1>
            <p style={{ fontSize: 12, color: COLOR.inkMuted, margin: "4px 0 0" }}>
              Live scan telemetry — last {summary?.window_hours ?? 24}h
            </p>
          </div>
          {connError && (
            <span style={{ fontSize: 12, color: COLOR.critical, border: `1px solid ${COLOR.critical}`, borderRadius: 6, padding: "3px 9px" }}>
              backend unreachable
            </span>
          )}
        </header>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12, marginBottom: 20 }}>
          <StatTile
            label="Success rate"
            value={summary ? `${summary.success_rate}%` : "--"}
            sub={summary ? `${summary.completed} ok / ${summary.hung} hung / ${summary.crashed} crashed` : ""}
            tone={successTone}
          />
          <StatTile
            label="Duration p50 / p90"
            value={summary ? `${summary.p50_duration_sec}s / ${summary.p90_duration_sec}s` : "--"}
            sub={summary?.p90_near_timeout ? "p90 near 30min timeout" : "within budget"}
            tone={durationTone}
          />
          <StatTile
            label="False-positive rate"
            value={summary ? `${summary.fp_rate}%` : "--"}
            sub={summary && summary.silent_zero_scanners.length > 0 ? `silent-zero: ${summary.silent_zero_scanners.join(", ")}` : "no silent-zero scanners"}
            tone={summary && summary.silent_zero_scanners.length > 0 ? "warning" : "good"}
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
    </div>
  );
}
