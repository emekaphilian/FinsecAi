"use client";

import { ChangeEvent, FormEvent, useEffect, useState } from "react";
import { apiFetch, getSession, scopedQuery } from "@/lib/api";

type Control = { id: string; control_id: string; title: string; control_text: string; status: string };
type DocumentRow = { id: string; document_type: string; name: string; version: string; issuer: string; status: string; controls: Control[] };

export default function GovernancePage() {
  const [documents, setDocuments] = useState<DocumentRow[]>([]);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [globalRegulation, setGlobalRegulation] = useState(false);
  const [documentType, setDocumentType] = useState("POLICY");
  const [canManage, setCanManage] = useState(false);
  const tenantId = typeof window === "undefined" ? null : new URLSearchParams(window.location.search).get("tenant_id") || getSession()?.tenant_id;

  async function load() {
    try { setDocuments(await apiFetch<DocumentRow[]>(`/governance/documents${scopedQuery(tenantId)}`)); }
    catch (error) { setMessage(error instanceof Error ? error.message : "Could not load governance documents."); }
  }
  useEffect(() => { setCanManage(["admin", "owner"].includes(getSession()?.role || "")); void load(); }, []);

  async function upload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const fields = new FormData(formElement);
    if (globalRegulation) fields.delete("tenant_id");
    else if (tenantId) fields.set("tenant_id", tenantId);
    setBusy(true); setMessage("");
    try {
      const result = await apiFetch<DocumentRow>("/governance/documents/upload", { method: "POST", body: fields });
      setMessage(`Uploaded ${result.name}. Review extracted controls below before they are used in investigations.`);
      formElement.reset(); setGlobalRegulation(false); await load();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Upload failed."); }
    finally { setBusy(false); }
  }

  async function review(controlId: string, approved: boolean) {
    try {
      await apiFetch(`/governance/controls/${controlId}/review?approved=${approved}${tenantId ? `&tenant_id=${encodeURIComponent(tenantId)}` : ""}`, { method: "POST" });
      await load();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Review failed."); }
  }

  return <div className="space-y-6">
    <div><h1 className="text-2xl font-semibold">Governance documents</h1><p className="text-sm text-text-secondary mt-2">Upload bank policies and CBN source documents. Extracted clauses require administrator review before investigations can match them.</p></div>
    {message && <p role="status" className="text-sm text-gold">{message}</p>}
    {canManage && <form onSubmit={upload} className="card grid gap-3 md:grid-cols-2">
      <h2 className="font-medium md:col-span-2">Upload a policy or regulation</h2>
      <select className="input" name="document_type" required value={documentType} onChange={(event: ChangeEvent<HTMLSelectElement>) => { setDocumentType(event.target.value); if (event.target.value !== "REGULATION") setGlobalRegulation(false); }}><option value="POLICY">Bank policy</option><option value="REGULATION">CBN regulation</option><option value="FRAMEWORK">Framework</option></select>
      <input className="input" name="name" placeholder="Document title" required />
      <input className="input" name="version" placeholder="Version" required />
      <input className="input" name="issuer" placeholder="Issuer (for example, Central Bank of Nigeria)" />
      <label className="text-sm text-text-secondary">Effective date<input className="input mt-1 w-full" name="effective_date" type="date" /></label>
      <label className="text-sm text-text-secondary">PDF or TXT<input className="input mt-1 w-full" name="file" type="file" accept=".pdf,.txt,application/pdf,text/plain" required /></label>
      {getSession()?.role === "owner" && documentType === "REGULATION" && <label className="md:col-span-2 flex items-center gap-2 text-sm text-text-secondary"><input type="checkbox" checked={globalRegulation} onChange={(event) => setGlobalRegulation(event.target.checked)} />Publish CBN regulation as a platform wide source</label>}
      <button className="btn-primary md:col-span-2" disabled={busy}>{busy ? "Processing..." : "Upload and extract clauses"}</button>
    </form>}
    <section className="space-y-4">
      {documents.length === 0 ? <div className="card text-sm text-text-secondary">No governance documents are registered for this workspace.</div> : documents.map((document) => <article className="card space-y-3" key={document.id}>
        <div className="flex flex-wrap justify-between gap-2"><div><h2 className="font-medium">{document.name} <span className="text-text-secondary">v{document.version}</span></h2><p className="text-xs text-text-secondary">{document.document_type} · {document.issuer || "Issuer not specified"}</p></div><span className="text-xs text-gold">{document.controls.filter((item) => item.status === "APPROVED").length} approved / {document.controls.length} extracted</span></div>
        {document.controls.map((control) => <div key={control.id} className="rounded-lg border border-border p-3"><div className="flex justify-between gap-3"><p className="text-sm font-medium">{control.control_id} · {control.title}</p><span className="text-xs text-text-secondary">{control.status}</span></div><p className="mt-2 text-xs text-text-secondary">{control.control_text}</p>{canManage && control.status === "PENDING" && <div className="mt-3 flex gap-2"><button className="btn-primary text-xs" onClick={() => void review(control.id, true)}>Approve</button><button className="border border-border rounded px-3 py-1 text-xs" onClick={() => void review(control.id, false)}>Reject</button></div>}</div>)}
      </article>)}
    </section>
  </div>;
}
