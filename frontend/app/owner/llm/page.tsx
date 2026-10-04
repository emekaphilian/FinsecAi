"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch, getSession } from "@/lib/api";

interface LlmStatus {
  provider: string | null;
  mode: string;
  detail?: string | null;
}

export default function LlmPage() {
  const [status, setStatus] = useState<LlmStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadStatus = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setStatus(await apiFetch<LlmStatus>("/copilot/status"));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to check the configured LLM provider.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (getSession()?.role === "owner") void loadStatus();
    else setLoading(false);
  }, [loadStatus]);

  if (getSession()?.role !== "owner") {
    return <p className="p-6 text-text-secondary">Platform owner access required.</p>;
  }

  const live = status?.mode === "live";
  return (
    <main className="p-6">
      <div className="max-w-4xl mx-auto space-y-6">
        <header className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-wide text-gold">Platform Owner</p>
            <h1 className="text-3xl font-semibold mt-2">LLM service</h1>
            <p className="text-text-secondary mt-2">Current backend provider readiness for copilot and investigation summaries.</p>
          </div>
          <button type="button" className="btn-primary text-sm" onClick={() => void loadStatus()} disabled={loading}>Check again</button>
        </header>

        {error && <p role="alert" className="text-sm text-danger">{error}</p>}
        <section className="card space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div><h2 className="font-medium">Provider status</h2><p className="text-xs text-text-secondary mt-1">Read-only health check; provider credentials are never exposed in the browser.</p></div>
            <span className={`rounded-full px-3 py-1 text-xs font-medium ${loading ? "bg-secondary text-text-secondary" : live ? "bg-success/15 text-success" : "bg-gold/15 text-gold"}`}>{loading ? "CHECKING" : live ? "LIVE" : (status?.mode || "UNKNOWN").replaceAll("_", " ").toUpperCase()}</span>
          </div>
          {loading ? <p className="text-sm text-text-secondary">Checking the configured provider…</p> : status ? (
            <dl className="grid gap-4 sm:grid-cols-2">
              <div><dt className="text-xs text-text-secondary">Provider</dt><dd className="mt-1 font-medium">{status.provider || "Not available"}</dd></div>
              <div><dt className="text-xs text-text-secondary">Runtime mode</dt><dd className="mt-1 font-medium">{status.mode.replaceAll("_", " ")}</dd></div>
              {status.detail && <div className="sm:col-span-2"><dt className="text-xs text-text-secondary">Readiness detail</dt><dd className="mt-1 text-sm">{status.detail}</dd></div>}
            </dl>
          ) : <p className="text-sm text-text-secondary">No status response is available.</p>}
        </section>
        <p className="text-sm text-text-secondary">Provider selection and secret configuration are managed by the backend deployment environment. This screen reports runtime readiness only.</p>
      </div>
    </main>
  );
}
