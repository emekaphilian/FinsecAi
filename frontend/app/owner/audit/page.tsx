"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch, getSession } from "@/lib/api";

interface AuditEvent {
  id: string;
  actor_user_id: string;
  tenant_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string;
  result: string;
  metadata: Record<string, unknown> | null;
  created_at: string;
}

const PAGE_SIZE = 100;

export default function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadEvents = useCallback(async (nextOffset: number) => {
    setLoading(true);
    setError(null);
    try {
      const result = await apiFetch<AuditEvent[]>(`/audit?limit=${PAGE_SIZE}&offset=${nextOffset}`);
      setEvents(result);
      setOffset(nextOffset);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to load the audit trail.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (getSession()?.role === "owner") void loadEvents(0);
    else setLoading(false);
  }, [loadEvents]);

  if (getSession()?.role !== "owner") {
    return <p className="p-6 text-text-secondary">Platform owner access required.</p>;
  }

  return (
    <main className="p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        <header className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-wide text-gold">Platform Owner</p>
            <h1 className="text-3xl font-semibold mt-2">Enterprise Audit</h1>
            <p className="text-text-secondary mt-2">Attributed activity within your authorized enterprise boundary.</p>
          </div>
          <button type="button" className="btn-primary text-sm" onClick={() => void loadEvents(offset)} disabled={loading}>Refresh</button>
        </header>

        {error && <p role="alert" className="text-sm text-danger">{error}</p>}
        <section className="card overflow-x-auto">
          <div className="flex justify-between items-center mb-4">
            <h2 className="font-medium">Audit events</h2>
            <span className="text-xs text-text-secondary">{loading ? "Loading…" : `${events.length} events`}</span>
          </div>
          {loading ? <p className="py-8 text-center text-sm text-text-secondary">Loading audit events…</p> : events.length === 0 ? (
            <p className="py-8 text-center text-sm text-text-secondary">No audit events were found.</p>
          ) : (
            <table className="w-full text-sm">
              <thead><tr className="border-b border-border text-left text-text-secondary"><th className="py-2 pr-4">Time</th><th className="py-2 pr-4">Action</th><th className="py-2 pr-4">Resource</th><th className="py-2 pr-4">Actor</th><th className="py-2 pr-4">Tenant</th><th className="py-2">Details</th></tr></thead>
              <tbody>{events.map((event) => (
                <tr key={event.id} className="border-b border-border/50 last:border-0 align-top">
                  <td className="py-3 pr-4 whitespace-nowrap">{new Date(event.created_at).toLocaleString()}</td>
                  <td className="py-3 pr-4"><span className="font-medium">{event.action}</span><span className="block text-xs text-text-secondary">{event.result}</span></td>
                  <td className="py-3 pr-4">{event.resource_type}<span className="block text-xs text-text-secondary break-all">{event.resource_id || "—"}</span></td>
                  <td className="py-3 pr-4 break-all">{event.actor_user_id || "System"}</td>
                  <td className="py-3 pr-4 break-all">{event.tenant_id || "Platform"}</td>
                  <td className="py-3">{event.metadata && Object.keys(event.metadata).length > 0 ? <details><summary className="cursor-pointer text-gold">View</summary><pre className="mt-2 max-w-md whitespace-pre-wrap break-all text-xs text-text-secondary">{JSON.stringify(event.metadata, null, 2)}</pre></details> : "—"}</td>
                </tr>
              ))}</tbody>
            </table>
          )}
          <div className="flex justify-between mt-4">
            <button type="button" className="text-sm text-gold disabled:text-text-secondary" disabled={loading || offset === 0} onClick={() => void loadEvents(Math.max(0, offset - PAGE_SIZE))}>Previous</button>
            <button type="button" className="text-sm text-gold disabled:text-text-secondary" disabled={loading || events.length < PAGE_SIZE} onClick={() => void loadEvents(offset + PAGE_SIZE)}>Next</button>
          </div>
        </section>
      </div>
    </main>
  );
}
