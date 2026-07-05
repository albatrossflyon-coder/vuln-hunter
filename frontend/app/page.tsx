"use client";

import { useState } from "react";
import ReactMarkdown from "react-markdown";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001";

type Finding = {
  rule_id: string;
  path: string;
  start_line: number;
  end_line: number;
  message: string;
  severity: string;
  cwe: string | null;
  owasp: string | null;
  snippet: string;
  explanation: string;
  exploitability: string;
  suggested_fix: string;
};

const EXPLOITABILITY_STYLES: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-400 text-black",
  low: "bg-blue-400 text-white",
  unknown: "bg-gray-300 text-black",
};

export default function Home() {
  const [repoPath, setRepoPath] = useState("");
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function runScan() {
    const path = repoPath.trim();
    if (!path || loading) return;

    setLoading(true);
    setError(null);
    setFindings(null);

    try {
      const res = await fetch(`${API_URL}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_path: path }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `Scan failed (${res.status})`);
      }

      const data = await res.json();
      setFindings(data.findings);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  }

  function toggle(i: number) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      return next;
    });
  }

  return (
    <div className="mx-auto flex min-h-full max-w-3xl flex-col px-4 py-6">
      <header className="mb-4 border-b border-black/10 pb-4">
        <h1 className="text-xl font-bold">Vuln Hunter</h1>
        <p className="text-sm text-black/60">
          Real static analysis (Semgrep) for detection, Claude for triage and fixes —
          not a freeform AI vulnerability guess.
        </p>
      </header>

      <div className="mb-4 flex gap-2 border-b border-black/10 pb-4">
        <input
          className="flex-1 rounded border border-black/20 px-3 py-2 text-sm"
          placeholder="Path to scan, e.g. C:\Repos\some-project"
          value={repoPath}
          onChange={(e) => setRepoPath(e.target.value)}
          disabled={loading}
          suppressHydrationWarning
        />
        <button
          onClick={runScan}
          disabled={loading || !repoPath.trim()}
          className="rounded bg-black px-4 py-2 text-sm font-bold text-white disabled:opacity-40"
        >
          {loading ? "Scanning…" : "Scan"}
        </button>
      </div>

      {error && <div className="mb-4 text-sm text-red-600">{error}</div>}

      {findings && findings.length === 0 && (
        <p className="text-sm text-black/40">No findings — clean scan.</p>
      )}

      <div className="flex-1 space-y-3 overflow-y-auto">
        {findings?.map((f, i) => (
          <div key={i} className="rounded border border-black/10">
            <button
              onClick={() => toggle(i)}
              className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
            >
              <div className="flex items-center gap-3">
                <span
                  className={`rounded px-2 py-0.5 text-xs font-bold uppercase ${
                    EXPLOITABILITY_STYLES[f.exploitability] ?? EXPLOITABILITY_STYLES.unknown
                  }`}
                >
                  {f.exploitability}
                </span>
                <span className="text-sm font-medium">{f.rule_id}</span>
              </div>
              <span className="text-xs text-black/40">
                {f.path.split(/[/\\]/).pop()}:{f.start_line}
              </span>
            </button>

            {expanded.has(i) && (
              <div className="space-y-3 border-t border-black/10 px-4 py-3 text-sm">
                <pre className="overflow-x-auto rounded bg-black/5 p-3 text-xs">
                  {f.snippet}
                </pre>
                <div>
                  <div className="mb-1 text-xs font-bold uppercase text-black/40">
                    Explanation
                  </div>
                  <p>{f.explanation}</p>
                </div>
                <div>
                  <div className="mb-1 text-xs font-bold uppercase text-black/40">
                    Suggested fix
                  </div>
                  <div className="prose prose-sm max-w-none prose-pre:text-xs">
                    <ReactMarkdown>{f.suggested_fix}</ReactMarkdown>
                  </div>
                </div>
                {(f.cwe || f.owasp) && (
                  <div className="text-xs text-black/40">
                    {f.cwe && <div>CWE: {f.cwe}</div>}
                    {f.owasp && <div>OWASP: {f.owasp}</div>}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
