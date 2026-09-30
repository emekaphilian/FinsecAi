"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiFetch, downloadReport, getSession, scopedQuery } from "@/lib/api";
import { Incident } from "@/lib/types";
import { RiskBadge } from "@/components/RiskBadge";

export default function IncidentsPage() {
  const canReset = ["admin", "owner"].includes(getSession()?.role || "");
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [uploading, setUploading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [isDemoTenant, setIsDemoTenant] = useState(false);
  const [dataMode, setDataMode] = useState<"demo_default" | "user_data" | null>(null);

  function selectedTenantId() {
    return new URLSearchParams(window.location.search).get("tenant_id");
  }

  function load() {
    setLoading(true);
    const tenantId = selectedTenantId();
    const path = tenantId
      ? `/incidents?limit=200&tenant_id=${encodeURIComponent(tenantId)}`
      : "/incidents?limit=200";
    Promise.all([
      apiFetch<Incident[]>(path),
      apiFetch<{ is_demo_tenant: boolean; mode: "demo_default" | "user_data" | null }>(
        `/incidents/data-mode${scopedQuery(tenantId)}`
      ),
    ])
      .then(([incidentRows, mode]) => {
        setIncidents(incidentRows);
        setIsDemoTenant(mode.is_demo_tenant);
        setDataMode(mode.mode);
      })
      .catch((error) => setMessage(error instanceof Error ? error.message : "Unable to load incidents."))
      .finally(() => setLoading(false));
  }

  useEffect(load, []);

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
  const file = e.target.files?.[0];
  if (!file) return;

  setUploading(true);
  setMessage(null);

  const form = new FormData();
  form.append("file", file);

  try {
    const res = await apiFetch<{
      created: number;
      skipped_duplicates: number;
      skipped_invalid?: number;
      scored_by_model?: boolean;
    }>(`/incidents/upload${scopedQuery(selectedTenantId())}`, {
      method: "POST",
      body: form,
    });

    setMessage(
      `Uploaded ${res.created} new incidents${
        res.skipped_duplicates
          ? ` (${res.skipped_duplicates} duplicates skipped)`
          : ""
      }${
        res.skipped_invalid
          ? ` (${res.skipped_invalid} invalid rows skipped)`
          : ""
      }.`
    );

    load();
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Upload failed.";

    setMessage(`Upload failed ? ${message}`);
  } finally {
    setUploading(false);
    e.target.value = "";
  }
}

async function handleAnalyzeAll() {
    setAnalyzing(true);
    setMessage(null);
    try {
    const tenantId = selectedTenantId();
      const path = tenantId
        ? `/incidents/analyze-batch?tenant_id=${encodeURIComponent(tenantId)}`
        : "/incidents/analyze-batch";
      const res = await apiFetch<{ analyzed: number; analysis_mode?: string }>(path, { method: 'POST' });
      setMessage(
        res.analyzed > 0
          ? `Analysis complete — ${res.analyzed} incidents analyzed.`
          : 'Nothing to analyze — all incidents already have results.'
      );
      load();
    } catch {
      setMessage('Analysis failed — check the backend logs.');
    } finally {
      setAnalyzing(false);
    }
  }

  async function handleReset() {
    if (!confirm('This deletes all incidents for this tenant. Continue?')) return;
    try {
      const res = await apiFetch<{ deleted: number }>(`/incidents/reset${scopedQuery(selectedTenantId())}`, { method: 'DELETE' });
      setMessage(`Deleted ${res.deleted} incidents.`);
      load();
    } catch (error) {
      setMessage(error instanceof Error ? `Reset failed: ${error.message}` : "Reset failed.");
    }
  }

  async function handleUseOwnData() {
    if (!confirm("This clears the default demo incidents and opens a blank workspace for your dataset. Continue?")) return;
    setMessage(null);
    try {
      await apiFetch<{ deleted: number }>(`/incidents/use-own-data${scopedQuery(selectedTenantId())}`, { method: "POST" });
      setMessage("Your blank test workspace is ready. Upload a compatible dataset to begin.");
      load();
    } catch (error) {
      setMessage(error instanceof Error ? `Could not switch data mode: ${error.message}` : "Could not switch data mode.");
    }
  }

  async function handleRestoreDemoData() {
    if (!confirm("This permanently replaces your uploaded test incidents with the default demo dataset. Continue?")) return;
    setMessage(null);
    try {
      const res = await apiFetch<{ restored: number }>(`/incidents/restore-demo-data${scopedQuery(selectedTenantId())}`, { method: "POST" });
      setMessage(`Default demo dataset restored (${res.restored} incidents).`);
      load();
    } catch (error) {
      setMessage(error instanceof Error ? `Restore failed: ${error.message}` : "Restore failed.");
    }
  }

  return (
    <div>
      <div className="flex flex-col gap-2 mb-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-semibold">Incidents</h1>
          <div className="flex gap-2">
            <button onClick={handleAnalyzeAll} disabled={analyzing} className="btn-primary text-sm">
              {analyzing ? 'Analyzing…' : 'Analyze all'}
            </button>
            <label className="btn-primary cursor-pointer text-sm">
              {uploading ? 'Uploading…' : 'Upload CSV'}
              <input type="file" accept=".csv,.json,.xls,.xlsx" className="hidden" onChange={handleUpload} />
            </label>
            {isDemoTenant && dataMode === "demo_default" && (
              <button onClick={handleUseOwnData} className="border border-gold/50 text-gold rounded-lg px-4 py-2 text-sm hover:bg-gold/10">
                Use my own data
              </button>
            )}
            {isDemoTenant && dataMode === "user_data" && (
              <button onClick={handleRestoreDemoData} className="border border-danger/50 text-danger rounded-lg px-4 py-2 text-sm hover:bg-danger/10">
                Reset demo data
              </button>
            )}
            {canReset && !isDemoTenant && <button onClick={handleReset} className="border border-danger/50 text-danger rounded-lg px-4 py-2 text-sm hover:bg-danger/10">
              Reset
            </button>}
          </div>
        </div>
        <p className="text-xs text-text-secondary mb-4">
          Supported formats: CSV, TXT, XLS, XLSX. Required columns: user_id, amount, risk_score, anomaly_score. Direct database and cloud-drive connectors are on the roadmap — not available yet.
        </p>
        {message && <p className="text-sm text-success">{message}</p>}
      </div>

      {isDemoTenant && dataMode === "user_data" && (
        <div className="card mb-4 border border-gold/30">
          <p className="text-sm font-medium">Your test dataset</p>
          <p className="text-xs text-text-secondary mt-1">
            Upload CSV, JSON, XLS, or XLSX records with <code>user_id</code> and <code>amount</code>.
            Include <code>risk_score</code> and <code>anomaly_score</code> as values from 0 to 1, or let the trained model score compatible rows.
          </p>
        </div>
      )}

      <div className="card overflow-x-auto">
        {loading ? (
          <p className="text-sm text-text-secondary py-6 text-center">Loading incidents…</p>
        ) : incidents.length === 0 ? (
          <p className="text-sm text-text-secondary py-6 text-center">No incidents yet — upload a CSV to get started.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-text-secondary border-b border-border">
                <th className="py-2 pr-4">ID</th>
                <th className="py-2 pr-4">User</th>
                <th className="py-2 pr-4">Amount</th>
                <th className="py-2 pr-4">Type</th>
                <th className="py-2 pr-4">Risk</th>
                <th className="py-2 pr-4">Confidence</th>
                <th className="py-2 pr-4">Governance</th>
                <th className="py-2 pr-4">MITRE</th>
                <th className="py-2 pr-4">Report</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((inc) => (
                <tr key={inc.id} className="border-b border-border/50 hover:bg-primary/40">
                  <td className="py-2 pr-4">
                    <Link href={`/dashboard/incidents/${inc.id}`} className="text-gold hover:underline">
                      {inc.id.slice(0, 8)}
                    </Link>
                  </td>
                  <td className="py-2 pr-4">{inc.user_id}</td>
                  <td className="py-2 pr-4">${inc.amount.toLocaleString(undefined, { maximumFractionDigits: 0 })}</td>
                  <td className="py-2 pr-4">{inc.transaction_type}</td>
                  <td className="py-2 pr-4">
                    <RiskBadge score={inc.risk_score} />
                  </td>
                  <td className="py-2 pr-4">{inc.confidence?.toFixed(2) ?? "—"}</td>
                  <td className="py-2 pr-4">
                    {inc.governance_flags ? (
                      <span className="badge badge-high">{inc.governance_flags.split(", ")[0]}</span>
                    ) : (
                      <span className="text-text-secondary">clear</span>
                    )}
                  </td>
                  <td className="py-2 pr-4 text-text-secondary">
                    {inc.mitre_techniques ? inc.mitre_techniques.split(", ")[0] : "—"}
                  </td>
                  <td className="py-2 pr-4">
                    <button
                      onClick={() => downloadReport(inc.id)}
                      disabled={!inc.explanation}
                      className="text-gold hover:underline disabled:text-text-secondary disabled:no-underline disabled:cursor-not-allowed"
                    >
                      Download
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
