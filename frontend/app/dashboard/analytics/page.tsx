"use client";

import { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, CartesianGrid } from "recharts";
import { apiFetch, getActiveTenantId, getSession, scopedQuery } from "@/lib/api";
import { AnalyticsSummary, PrecisionRecall, DriftResult } from "@/lib/types";
import { KpiCard } from "@/components/KpiCard";

export default function AnalyticsPage() {
  const [pr, setPr] = useState<PrecisionRecall | null>(null);
  const [drift, setDrift] = useState<DriftResult | null>(null);
  const [fairness, setFairness] = useState<Record<string, { positive_rate: number; count: number }> | null>(null);
  const [governance, setGovernance] = useState<{ compliance_status: string; critical_rate: number } | null>(null);
  const [summary, setSummary] = useState<AnalyticsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const session = getSession();
    const requestedTenantId = new URLSearchParams(window.location.search).get("tenant_id");
    const tenantId = session?.role === "owner" ? requestedTenantId : getActiveTenantId() || session?.tenant_id;
    const scope = scopedQuery(tenantId);
    Promise.allSettled([
      apiFetch<PrecisionRecall>(`/analytics/precision-recall${scope}`),
      apiFetch<DriftResult>(`/analytics/drift${scope}`),
      apiFetch<Record<string, { positive_rate: number; count: number }>>(`/analytics/fairness${scope}`),
      apiFetch<{ compliance_status: string; critical_rate: number }>(`/analytics/governance${scope}`),
      apiFetch<AnalyticsSummary>(`/analytics/summary${scope}`),
    ]).then((results) => {
      const [pr, drift, fairness, governance, summary] = results;
      if (pr.status === "fulfilled") setPr(pr.value);
      if (drift.status === "fulfilled") setDrift(drift.value);
      if (fairness.status === "fulfilled") setFairness(fairness.value);
      if (governance.status === "fulfilled") setGovernance(governance.value);
      if (summary.status === "fulfilled") setSummary(summary.value);
      const failed = results.find((result) => result.status === "rejected");
      if (failed?.status === "rejected") {
        setError(failed.reason instanceof Error ? failed.reason.message : "Unable to load some analytics.");
      }
    });
  }, []);

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-2">Analytics</h1>
      <p className="text-sm text-text-secondary mb-6">
        Computed at a 0.5 risk threshold over {summary?.total_incidents ?? "—"} incidents.
        Ground-truth labels are synthetic pending analyst-confirmed outcomes — treat these as
        pipeline-health checks, not production accuracy.
      </p>
      {error && <p role="alert" className="mb-4 text-sm text-danger">{error}</p>}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <KpiCard label="Precision" value={pr?.precision.toFixed(3) ?? "—"} />
        <KpiCard label="Recall" value={pr?.recall.toFixed(3) ?? "—"} />
        <KpiCard label="F1 score" value={pr?.f1.toFixed(3) ?? "—"} />
        <KpiCard label="True positives" value={pr?.true_positives ?? "—"} />
      </div>

      <div className="card mb-4">
        <p className="text-sm font-medium mb-3">Confusion matrix breakdown</p>
        <ResponsiveContainer width="100%" height={260}>
          <BarChart
            data={[
              { name: "True positive", count: pr?.true_positives ?? 0 },
              { name: "False positive", count: pr?.false_positives ?? 0 },
              { name: "False negative", count: pr?.false_negatives ?? 0 },
              { name: "True negative", count: pr?.true_negatives ?? 0 },
            ]}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="name" interval={0} angle={-12} textAnchor="end" height={48} tick={{ fill: "#CBD5E1", fontSize: 11 }} />
            <YAxis tick={{ fill: "#CBD5E1", fontSize: 11 }} />
            <Tooltip contentStyle={{ background: "#1E293B", border: "1px solid #334155" }} />
            <Bar dataKey="count" fill="#F59E0B" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="card">
          <p className="text-sm font-medium mb-1">Drift (PSI)</p>
          <p className="text-xs text-text-secondary mb-3">
            How much the predicted-positive rate shifted between the first and second half
            of this batch — a pipeline stability check, not a compliance measure.
          </p>
          <p className="text-2xl font-semibold text-gold mb-1">{drift?.drift_score ?? "—"}</p>
          <p className="text-xs text-text-secondary uppercase">{drift?.status}</p>
        </div>

        <div className="card">
          <p className="text-sm font-medium mb-1">Governance compliance</p>
          <p className="text-xs text-text-secondary mb-3">
            Share of incidents carrying at least one governance flag
            {summary && ` (${summary.governance_flags_count} of ${summary.total_incidents})`}.
          </p>
          <p className="text-2xl font-semibold text-gold mb-1">
            {governance ? `${(governance.critical_rate * 100).toFixed(1)}%` : "—"}
          </p>
          <p className="text-xs text-text-secondary uppercase">{governance?.compliance_status}</p>
        </div>

        <div className="card col-span-2">
          <p className="text-sm font-medium mb-3">Fairness by transaction amount</p>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart
              data={fairness ? Object.entries(fairness).map(([segment, data]) => ({ segment, rate: data.positive_rate * 100 })) : []}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="segment" tick={{ fill: "#CBD5E1", fontSize: 11 }} />
              <YAxis tick={{ fill: "#CBD5E1", fontSize: 11 }} unit="%" />
              <Tooltip contentStyle={{ background: "#1E293B", border: "1px solid #334155" }} />
              <Bar dataKey="rate" fill="#60A5FA" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
