"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiFetch, downloadReport, getSession } from "@/lib/api";
import { EnterpriseSummary, Incident, Tenant } from "@/lib/types";

export default function EnterpriseReportsPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [summary, setSummary] = useState<EnterpriseSummary | null>(null);
  const [tenantId, setTenantId] = useState("");
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loadingOverview, setLoadingOverview] = useState(true);
  const [loadingIncidents, setLoadingIncidents] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function downloadEnterpriseReport() {
    if (!summary) return;
    const rows: (string | number)[][] = [
      ["Section", "Metric", "Tenant", "Type", "Status", "Users", "Incidents", "Evidence", "Report jobs", "Value"],
      ["Enterprise", "Tenants", "", "", "", "", "", "", "", summary.total_tenants],
      ["Enterprise", "Active customer tenants", "", "", "", "", "", "", "", summary.active_customer_tenants],
      ["Enterprise", "Demo tenants", "", "", "", "", "", "", "", summary.demo_tenants],
      ["Enterprise", "Incidents", "", "", "", "", "", "", "", summary.total_incidents],
      ["Enterprise", "High-risk incidents", "", "", "", "", "", "", "", summary.high_risk_incidents],
      ["Enterprise", "Completed reports", "", "", "", "", "", "", "", summary.reports_generated],
      ...tenants.map((tenant) => [
        "Tenant",
        "Workspace activity",
        tenant.name,
        tenant.tenant_type || "",
        tenant.status,
        tenant.user_count,
        tenant.incident_count,
        tenant.evidence_count,
        tenant.report_count,
        "",
      ]),
    ];
    const csv = rows.map((row) => row.map((value) => `"${String(value).replaceAll('"', '""')}"`).join(",")).join("\r\n");
    const url = URL.createObjectURL(new Blob([`\uFEFF${csv}`], { type: "text/csv;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `finsecai-enterprise-report-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  }

  useEffect(() => {
    if (getSession()?.role !== "owner") return;
    Promise.all([
      apiFetch<Tenant[]>("/tenants"),
      apiFetch<EnterpriseSummary>("/analytics/enterprise-summary"),
    ])
      .then(([tenantData, summaryData]) => {
        setTenants(tenantData);
        setSummary(summaryData);
        setTenantId((current) => current || tenantData[0]?.id || "");
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : "Unable to load enterprise report data."))
      .finally(() => setLoadingOverview(false));
  }, []);

  useEffect(() => {
    if (!tenantId || getSession()?.role !== "owner") {
      setIncidents([]);
      return;
    }
    let cancelled = false;
    setLoadingIncidents(true);
    setError(null);
    apiFetch<Incident[]>(`/incidents?limit=200&tenant_id=${encodeURIComponent(tenantId)}`)
      .then((data) => {
        if (!cancelled) setIncidents(data.filter((incident) => Boolean(incident.analysis_json?.data_provenance)));
      })
      .catch((reason) => {
        if (!cancelled) setError(reason instanceof Error ? reason.message : "Unable to load report-ready incidents.");
      })
      .finally(() => {
        if (!cancelled) setLoadingIncidents(false);
      });
    return () => { cancelled = true; };
  }, [tenantId]);

  const selectedTenant = tenants.find((tenant) => tenant.id === tenantId);

  if (getSession()?.role !== "owner") {
    return <p className="p-6 text-text-secondary">Platform owner access required.</p>;
  }

  return (
    <main className="p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        <header>
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="text-xs uppercase tracking-wide text-gold">Platform Owner</p>
              <h1 className="text-3xl font-semibold mt-2">Enterprise Reports</h1>
              <p className="text-text-secondary mt-2">Review report activity across customer workspaces and download incident reports from a selected tenant.</p>
            </div>
            <button type="button" className="btn-primary text-sm" onClick={downloadEnterpriseReport} disabled={loadingOverview || !summary}>Download enterprise CSV</button>
          </div>
        </header>

        {error && <p role="alert" className="text-sm text-danger">{error}</p>}

        <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="card"><p className="text-sm text-text-secondary">Tenants</p><p className="text-2xl font-semibold mt-2">{loadingOverview ? "…" : summary?.total_tenants ?? "—"}</p></div>
          <div className="card"><p className="text-sm text-text-secondary">Incidents</p><p className="text-2xl font-semibold mt-2">{loadingOverview ? "…" : summary?.total_incidents ?? "—"}</p></div>
          <div className="card"><p className="text-sm text-text-secondary">High-risk incidents</p><p className="text-2xl font-semibold mt-2">{loadingOverview ? "…" : summary?.high_risk_incidents ?? "—"}</p></div>
          <div className="card"><p className="text-sm text-text-secondary">Completed report jobs</p><p className="text-2xl font-semibold mt-2">{loadingOverview ? "…" : summary?.reports_generated ?? "—"}</p></div>
        </section>

        <section className="card space-y-4">
          <div>
            <h2 className="font-medium">Tenant report activity</h2>
            <p className="text-xs text-text-secondary mt-1">Counts come from each tenant workspace. Select a tenant to see incidents eligible for PDF generation.</p>
          </div>
          {loadingOverview ? <p className="text-sm text-text-secondary">Loading enterprise report data…</p> : tenants.length === 0 ? (
            <p className="text-sm text-text-secondary">No customer or demo workspaces are available.</p>
          ) : (
            <div className="divide-y divide-border">
              {tenants.map((tenant) => (
                <button key={tenant.id} type="button" onClick={() => setTenantId(tenant.id)} className={`w-full py-3 flex flex-wrap items-center justify-between gap-3 text-left ${tenant.id === tenantId ? "text-gold" : "hover:text-gold"}`}>
                  <span><span className="font-medium">{tenant.name}</span><span className="block text-xs text-text-secondary mt-1">{tenant.tenant_type || "Unclassified"} · {tenant.status} · {tenant.incident_count} incidents</span></span>
                  <span className="text-sm">{tenant.report_count} report jobs</span>
                </button>
              ))}
            </div>
          )}
        </section>

        <section className="card overflow-x-auto">
          <div className="flex flex-wrap justify-between items-end gap-4 mb-4">
            <div>
              <h2 className="font-medium">Report-ready incidents</h2>
              <p className="text-xs text-text-secondary mt-1">{selectedTenant ? selectedTenant.name : "Choose a tenant"} · persisted source-aware analysis required</p>
            </div>
            <span className="text-xs text-text-secondary">{loadingIncidents ? "Loading…" : `${incidents.length} ready`}</span>
          </div>
          {!tenantId ? <p className="py-6 text-center text-sm text-text-secondary">Select a tenant with incidents to review reports.</p> : loadingIncidents ? (
            <p className="py-6 text-center text-sm text-text-secondary">Loading report-ready incidents…</p>
          ) : incidents.length === 0 ? (
            <div className="py-6 text-center text-sm text-text-secondary">No analyzed incidents with persisted provenance are ready for a report.</div>
          ) : (
            <table className="w-full text-sm">
              <thead><tr className="border-b border-border text-left text-text-secondary"><th className="py-2 pr-4">Incident</th><th className="py-2 pr-4">User</th><th className="py-2 pr-4">Risk</th><th className="py-2 pr-4">Created</th><th className="py-2">Action</th></tr></thead>
              <tbody>{incidents.map((incident) => (
                <tr key={incident.id} className="border-b border-border/50 last:border-0">
                  <td className="py-3 pr-4"><Link href={`/dashboard/incidents/${encodeURIComponent(incident.id)}?tenant_id=${encodeURIComponent(tenantId)}`} className="text-gold hover:underline">{incident.id.slice(0, 8)}</Link></td>
                  <td className="py-3 pr-4">{incident.user_id}</td>
                  <td className="py-3 pr-4">{incident.risk_score.toFixed(2)}</td>
                  <td className="py-3 pr-4">{incident.created_at ? new Date(incident.created_at).toLocaleDateString() : "—"}</td>
                  <td className="py-3"><button type="button" className="text-gold hover:underline" onClick={() => downloadReport(incident.id)}>Download PDF</button></td>
                </tr>
              ))}</tbody>
            </table>
          )}
        </section>
      </div>
    </main>
  );
}
