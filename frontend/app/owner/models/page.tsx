"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch, getSession } from "@/lib/api";

interface ModelVersion {
  version: string;
  is_active: boolean;
  trained_at?: string | null;
  training_data_source?: string | null;
  eval_metrics?: Record<string, number | string | null> | null;
}

interface DriftStatus {
  active_model_version: string | null;
  drift: { drift_score?: number; status?: string };
}

export default function ModelsPage() {
  const [versions, setVersions] = useState<ModelVersion[]>([]);
  const [drift, setDrift] = useState<DriftStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [changingVersion, setChangingVersion] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const results = await Promise.allSettled([
      apiFetch<{ versions: ModelVersion[] }>("/ml/versions"),
      apiFetch<DriftStatus>("/ml/drift"),
    ]);
    const [versionResult, driftResult] = results;
    if (versionResult.status === "fulfilled") setVersions(versionResult.value.versions);
    if (driftResult.status === "fulfilled") setDrift(driftResult.value);
    const failure = results.find((result) => result.status === "rejected");
    if (failure?.status === "rejected") {
      setError(failure.reason instanceof Error ? failure.reason.message : "Unable to load model operations data.");
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    if (getSession()?.role === "owner") void load();
    else setLoading(false);
  }, [load]);

  async function activateVersion(version: string) {
    if (!window.confirm(`Switch the active model to ${version}?`)) return;
    setChangingVersion(version);
    setError(null);
    setMessage(null);
    try {
      await apiFetch(`/ml/rollback?version=${encodeURIComponent(version)}`, { method: "POST" });
      setMessage(`Active model switched to ${version}.`);
      await load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to change the active model.");
    } finally {
      setChangingVersion(null);
    }
  }

  if (getSession()?.role !== "owner") {
    return <p className="p-6 text-text-secondary">Platform owner access required.</p>;
  }

  return (
    <main className="p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        <header className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-wide text-gold">Platform Owner</p>
            <h1 className="text-3xl font-semibold mt-2">Models</h1>
            <p className="text-text-secondary mt-2">Inspect registered model versions, current drift, and switch the active version.</p>
          </div>
          <button type="button" className="btn-primary text-sm" onClick={() => void load()} disabled={loading}>Refresh</button>
        </header>

        {error && <p role="alert" className="text-sm text-danger">{error}</p>}
        {message && <p role="status" className="text-sm text-success">{message}</p>}

        <section className="grid gap-4 sm:grid-cols-3">
          <div className="card"><p className="text-sm text-text-secondary">Active model</p><p className="mt-2 font-medium break-all">{drift?.active_model_version || "None registered"}</p></div>
          <div className="card"><p className="text-sm text-text-secondary">Drift score</p><p className="mt-2 text-2xl font-semibold">{drift?.drift?.drift_score ?? "—"}</p></div>
          <div className="card"><p className="text-sm text-text-secondary">Drift status</p><p className="mt-2 font-medium">{drift?.drift?.status || "Unavailable"}</p></div>
        </section>

        <section className="card overflow-x-auto">
          <div className="flex items-center justify-between mb-4"><h2 className="font-medium">Registered versions</h2><span className="text-xs text-text-secondary">{loading ? "Loading…" : `${versions.length} versions`}</span></div>
          {loading ? <p className="py-8 text-center text-sm text-text-secondary">Loading model registry…</p> : versions.length === 0 ? (
            <p className="py-8 text-center text-sm text-text-secondary">No model versions are registered on this backend.</p>
          ) : (
            <table className="w-full text-sm">
              <thead><tr className="border-b border-border text-left text-text-secondary"><th className="py-2 pr-4">Version</th><th className="py-2 pr-4">Trained</th><th className="py-2 pr-4">Training data</th><th className="py-2 pr-4">Evaluation</th><th className="py-2">Action</th></tr></thead>
              <tbody>{versions.map((model) => (
                <tr key={model.version} className="border-b border-border/50 last:border-0 align-top">
                  <td className="py-3 pr-4 break-all">{model.version}{model.is_active && <span className="ml-2 text-xs text-success">ACTIVE</span>}</td>
                  <td className="py-3 pr-4 whitespace-nowrap">{model.trained_at ? new Date(model.trained_at).toLocaleString() : "—"}</td>
                  <td className="py-3 pr-4">{model.training_data_source || "—"}</td>
                  <td className="py-3 pr-4">{model.eval_metrics && Object.keys(model.eval_metrics).length ? <details><summary className="cursor-pointer text-gold">View metrics</summary><dl className="mt-2 space-y-1 text-xs">{Object.entries(model.eval_metrics).map(([key, value]) => <div key={key} className="flex justify-between gap-4"><dt>{key.replaceAll("_", " ")}</dt><dd>{value ?? "—"}</dd></div>)}</dl></details> : "—"}</td>
                  <td className="py-3">{model.is_active ? "Current" : <button type="button" className="text-gold hover:underline disabled:opacity-50" disabled={changingVersion !== null} onClick={() => void activateVersion(model.version)}>{changingVersion === model.version ? "Switching…" : "Make active"}</button>}</td>
                </tr>
              ))}</tbody>
            </table>
          )}
        </section>
      </div>
    </main>
  );
}
