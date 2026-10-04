"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiFetch, getSession } from "@/lib/api";
import { Tenant } from "@/lib/types";

export default function IntegrationsPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (getSession()?.role !== "owner") {
      setLoading(false);
      return;
    }
    apiFetch<Tenant[]>("/tenants")
      .then(setTenants)
      .catch((reason) => setError(reason instanceof Error ? reason.message : "Unable to load workspace configuration status."))
      .finally(() => setLoading(false));
  }, []);

  if (getSession()?.role !== "owner") {
    return <p className="p-6 text-text-secondary">Platform owner access required.</p>;
  }

  const configuredCount = tenants.filter((tenant) => tenant.configured).length;
  return (
    <main className="p-6">
      <div className="max-w-6xl mx-auto space-y-6">
        <header>
          <p className="text-xs uppercase tracking-wide text-gold">Platform Owner</p>
          <h1 className="text-3xl font-semibold mt-2">Integrations</h1>
          <p className="text-text-secondary mt-2">Workspace configuration overview across the enterprise.</p>
        </header>

        {error && <p role="alert" className="text-sm text-danger">{error}</p>}
        <section className="grid gap-4 sm:grid-cols-3">
          <div className="card"><p className="text-sm text-text-secondary">Workspaces</p><p className="text-2xl font-semibold mt-2">{loading ? "…" : tenants.length}</p></div>
          <div className="card"><p className="text-sm text-text-secondary">Workspace profiles configured</p><p className="text-2xl font-semibold mt-2">{loading ? "…" : configuredCount}</p></div>
          <div className="card"><p className="text-sm text-text-secondary">Profiles not configured</p><p className="text-2xl font-semibold mt-2">{loading ? "…" : tenants.length - configuredCount}</p></div>
        </section>

        <section className="card">
          <h2 className="font-medium">Workspace profile status</h2>
          <p className="text-xs text-text-secondary mt-1 mb-4">Configured indicates that a tenant profile record exists; it does not imply a live external connector.</p>
          {loading ? <p className="text-sm text-text-secondary">Loading workspace status…</p> : tenants.length === 0 ? (
            <p className="py-6 text-center text-sm text-text-secondary">No workspaces are available.</p>
          ) : (
            <div className="divide-y divide-border">{tenants.map((tenant) => (
              <div key={tenant.id} className="py-3 flex flex-wrap items-center justify-between gap-3">
                <div><p className="font-medium">{tenant.name}</p><p className="text-xs text-text-secondary mt-1">{tenant.tenant_type || "Unclassified"} · {tenant.status}</p></div>
                <div className="flex items-center gap-4"><span className={`text-xs ${tenant.configured ? "text-success" : "text-text-secondary"}`}>{tenant.configured ? "Profile configured" : "No profile"}</span><Link href={`/owner/tenants/${encodeURIComponent(tenant.id)}`} className="text-sm text-gold hover:underline">View workspace</Link></div>
              </div>
            ))}</div>
          )}
        </section>

        <aside className="rounded-lg border border-border bg-secondary/40 p-4 text-sm text-text-secondary">
          External integration connectors and connection testing are not currently exposed by the backend. This page shows workspace profile status only; it does not claim to verify a bank, cloud-drive, or third-party connection.
        </aside>
      </div>
    </main>
  );
}
