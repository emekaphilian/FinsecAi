"use client";

import { useEffect, useState } from "react";
import { useParams, useSearchParams } from "next/navigation";
import { apiFetch, downloadReport } from "@/lib/api";
import { Incident } from "@/lib/types";
import { RiskBadge } from "@/components/RiskBadge";
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

interface HistoricalTransaction {
  incident_id: string;
  transaction_id: string;
  timestamp: string | null;
  amount: number;
  currency?: string | null;
  transaction_type: string;
  channel?: string | null;
  device_id?: string | null;
  device_name?: string | null;
  location?: string | null;
  origin_city?: string | null;
  origin_country?: string | null;
  ip_address?: string | null;
  source_account?: string | null;
  account_age_days?: number | string | null;
  risk_score: number;
  anomaly_score: number;
  is_incident: boolean;
}

interface TransactionHistory {
  lookback_days: number;
  as_of: string;
  historical_transaction_count: number;
  transaction_count: number;
  truncated: boolean;
  dataset_source?: string | null;
  dataset_id?: string | null;
  transactions: HistoricalTransaction[];
  activity: {
    daily_counts: { date: string; count: number; contains_incident: boolean }[];
    velocity_24h_series: { transaction_id: string; timestamp: string | null; count: number; is_incident: boolean }[];
  };
  baseline: {
    comparable_transaction_count: number;
    transaction_type: string;
    average_amount: number | null;
    current_amount: number;
    amount_variance_percent: number | null;
    channel_counts: Record<string, number>;
    channel_usage: Record<string, { count: number; percent: number | null }>;
    current_channel?: string | null;
    current_channel_percent: number | null;
    typical_locations: { location: string; count: number }[];
    current_location?: string | null;
    velocity_24h: number;
    similar_transactions: HistoricalTransaction[];
  };
  profile: {
    account_name?: string | null;
    account_age_days?: number | string | null;
    source_accounts: string[];
    devices: string[];
    known_ips: string[];
    transaction_count: number;
    transaction_volume: number;
    average_transaction: number | null;
    transaction_types: Record<string, number>;
    channels: Record<string, number>;
    typical_locations: { location: string; count: number }[];
  };
  findings: {
    finding: string;
    status: string;
    summary: string;
    historical_mean?: number | null;
    variance_percent?: number | null;
    historical_origins?: string[];
    current_origin?: string | null;
    supporting_transaction_ids: string[];
  }[];
}

interface MappingExplanation {
  tier?: string;
  rationale: string | string[];
  mitre: { id: string; name: string }[];
  nist: { id: string; name: string }[];
}

function formatMoney(amount: number, currency?: string | null): string {
  if (currency) {
    try {
      return new Intl.NumberFormat(undefined, {
        style: "currency",
        currency,
        maximumFractionDigits: 2,
      }).format(amount);
    } catch {
      return `${currency} ${amount.toLocaleString(undefined, { maximumFractionDigits: 2 })}`;
    }
  }
  return amount.toLocaleString(undefined, { maximumFractionDigits: 2 });
}

function formatDate(timestamp: string | null): string {
  if (!timestamp) return "Unknown date";
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime())
    ? "Unknown date"
    : date.toLocaleDateString(undefined, { month: "short", day: "2-digit" });
}

function formatCounts(counts: Record<string, number>): string {
  const entries = Object.entries(counts);
  return entries.length ? entries.map(([label, count]) => `${label} (${count})`).join(", ") : "Not supplied";
}

function downloadEvidenceCsv(history: TransactionHistory, investigationFindings: any[], retrievedEvidence: any[], validation?: { status?: string }) {
  const columns = ["record_type", "record_id", "timestamp", "amount", "currency", "transaction_type", "channel", "location", "risk_score", "anomaly_score", "finding", "status", "summary", "supporting_record_ids"];
  const escape = (value: unknown) => `"${String(value ?? "").replaceAll('"', '""')}"`;
  const transactionRows = history.transactions.map((row) => [
    row.is_incident ? "incident" : "historical_transaction", row.transaction_id, row.timestamp,
    row.amount, row.currency, row.transaction_type, row.channel, row.location,
    row.risk_score, row.anomaly_score, "", "", "", "",
  ]);
  const findingRows = history.findings.map((finding) => [
    "historical_finding", "", "", "", "", "", "", "", "", "",
    finding.finding, finding.status, finding.summary, finding.supporting_transaction_ids.join("; "),
  ]);
  const aiFindingRows = investigationFindings.map((finding) => [
    "ai_finding", "", "", "", "", "", "", "", "", "",
    finding.finding, finding.severity, finding.rationale || finding.observed_signal,
    (finding.supporting_evidence || []).join("; "),
  ]);
  const retrievedEvidenceRows = retrievedEvidence.map((item) => [
    "retrieved_evidence", item.evidence_id, "", "", "", "", "", "", "", "",
    item.framework_id || "Reference evidence", item.source, item.text,
    item.evidence_id,
  ]);
  const metadataRows = [
    ["investigation_metadata", history.dataset_id, history.as_of, "", "", "", "", "", "", "", "Data provenance", history.dataset_source, `${history.lookback_days}-day lookback`, ""],
    ["validation", "", "", "", "", "", "", "", "", "", "Investigation validation", validation?.status, JSON.stringify(validation || {}), ""],
  ];
  const csv = [columns, ...metadataRows, ...transactionRows, ...findingRows, ...aiFindingRows, ...retrievedEvidenceRows].map((row) => row.map(escape).join(",")).join("\r\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `investigation-evidence-${history.dataset_id || "dataset"}.csv`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function ProfileValue({ label, value }: { label: string; value: string | number | null | undefined }) {
  return <div className="rounded-lg border border-border/60 bg-background/40 p-3"><p className="text-[11px] uppercase tracking-wide text-text-secondary">{label}</p><p className="mt-1 break-words font-medium">{value === null || value === undefined || value === "" ? "Not supplied" : value}</p></div>;
}

function ProfileRiskTrend({ rows }: { rows: HistoricalTransaction[] }) {
  return <div className="mt-4 rounded-lg border border-border/60 bg-background/40 p-3">
    <p className="text-[11px] uppercase tracking-wide text-text-secondary">Historical risk trend</p>
    {rows.length < 2 ? <p className="mt-2 text-xs text-text-secondary">Not enough dated transactions to show a trend.</p> : <div className="mt-2 h-36">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={rows} margin={{ top: 8, right: 12, bottom: 4, left: -18 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis dataKey="timestamp" tick={{ fill: "#CBD5E1", fontSize: 10 }} tickFormatter={(stamp) => stamp ? formatDate(stamp) : "—"} interval="preserveStartEnd" />
          <YAxis domain={[0, 1]} tick={{ fill: "#CBD5E1", fontSize: 10 }} />
          <Tooltip contentStyle={{ background: "#1E293B", border: "1px solid #334155" }} labelFormatter={(stamp) => stamp ? new Date(stamp).toLocaleString() : "Unknown date"} />
          <Line type="monotone" dataKey="risk_score" name="Risk score" stroke="#F59E0B" strokeWidth={2} activeDot={{ r: 5 }} dot={(props) => props.payload?.is_incident ? <circle cx={props.cx} cy={props.cy} r={6} fill="#F59E0B" stroke="#fff" strokeWidth={2} /> : <g />} />
        </LineChart>
      </ResponsiveContainer>
    </div>}
  </div>;
}

function BaselineRow({ label, historical, current, comparison }: { label: string; historical: string; current: string; comparison: string }) {
  return <tr className="border-b border-border/40"><td className="py-2 pr-3 font-medium">{label}</td><td className="py-2 pr-3 text-text-secondary">{historical}</td><td className="py-2 pr-3">{current}</td><td className="py-2 pr-3">{comparison}</td></tr>;
}

function TimelineRail({ rows }: { rows: HistoricalTransaction[] }) {
  const first = rows[0]?.timestamp ? new Date(rows[0].timestamp).getTime() : 0;
  const last = rows.at(-1)?.timestamp ? new Date(rows.at(-1)!.timestamp!).getTime() : first;
  const span = Math.max(1, last - first);
  return <div className="relative overflow-x-auto py-2">
    <div className="relative min-w-[640px] h-16">
      <div className="absolute left-2 right-2 top-7 h-px bg-border" />
      {rows.map((row, index) => {
        const time = row.timestamp ? new Date(row.timestamp).getTime() : first;
        const left = rows.length === 1 ? 50 : 3 + ((time - first) / span) * 94;
        const high = row.risk_score >= 0.7;
        return <div key={row.incident_id} className="absolute top-0 -translate-x-1/2" style={{ left: `${left}%` }} title={`${row.transaction_id} · ${formatDate(row.timestamp)} · ${formatMoney(row.amount, row.currency)}`}>
          <span className={`block mx-auto mt-5 h-3 w-3 rounded-full border-2 ${row.is_incident ? "h-5 w-5 -mt-1 border-gold bg-gold" : high ? "border-danger bg-danger/70" : "border-success bg-success/70"}`} />
          {(index === 0 || index === rows.length - 1 || row.is_incident || rows.length <= 8) && <span className={`mt-1 block whitespace-nowrap text-center text-[10px] ${row.is_incident ? "font-semibold text-gold" : "text-text-secondary"}`}>{row.is_incident ? "INCIDENT" : formatDate(row.timestamp)}</span>}
        </div>;
      })}
    </div>
    <div className="flex justify-between text-[10px] text-text-secondary"><span>{formatDate(rows[0]?.timestamp ?? null)}</span><span>Chronological · {rows.length} rows</span><span>{formatDate(rows.at(-1)?.timestamp ?? null)}</span></div>
  </div>;
}

function TrendCard({ title, subtitle, rows, value, secondary }: { title: string; subtitle: string; rows: HistoricalTransaction[]; value: "amount" | "risk_score"; secondary?: "anomaly_score" }) {
  const width = 600;
  const height = 180;
  const padX = 20;
  const padY = 16;
  const values = rows.map((row) => row[value]);
  const min = value === "amount" ? Math.min(0, ...values) : 0;
  const max = value === "amount" ? Math.max(1, ...values) : 1;
  const x = (index: number) => padX + (rows.length <= 1 ? 0 : index / (rows.length - 1)) * (width - padX * 2);
  const y = (number: number) => height - padY - ((number - min) / Math.max(0.0001, max - min)) * (height - padY * 2);
  const points = (key: "amount" | "risk_score" | "anomaly_score") => rows.map((row, index) => `${x(index)},${y(key === "amount" ? row.amount : row[key])}`).join(" ");
  return <div className="card min-w-0">
    <p className="text-sm font-medium">{title}</p><p className="text-xs text-text-secondary mt-1">{subtitle}</p>
    {rows.length < 2 ? <p className="text-sm text-text-secondary py-8">Not enough transactions to show a trend.</p> : <>
      <div className="overflow-x-auto mt-3"><svg viewBox={`0 0 ${width} ${height}`} className="w-full min-w-[460px] h-48" role="img" aria-label={title}>
        {[0, 0.5, 1].map((fraction) => <line key={fraction} x1={padX} x2={width - padX} y1={padY + fraction * (height - padY * 2)} y2={padY + fraction * (height - padY * 2)} stroke="currentColor" className="text-border" strokeDasharray="3 5" />)}
        <polyline points={points(value)} fill="none" stroke="currentColor" strokeWidth="2.5" className="text-gold" />
        {secondary && <polyline points={points(secondary)} fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray="5 4" className="text-danger" />}
        {rows.map((row, index) => row.is_incident && <circle key={row.incident_id} cx={x(index)} cy={y(value === "amount" ? row.amount : row[value])} r="6" fill="currentColor" className="text-gold" stroke="white" strokeWidth="2" />)}
      </svg></div>
      <div className="flex flex-wrap gap-4 text-xs text-text-secondary"><span><i className="inline-block mr-1 h-2 w-2 rounded-full bg-gold" />{value === "amount" ? "Transaction amount" : "Risk score"}</span>{secondary && <span><i className="inline-block mr-1 h-2 w-2 rounded-full bg-danger" />Anomaly score</span>}<span className="text-gold">Outlined point = incident</span></div>
    </>}
  </div>;
}

function ActivityAnalytics({ activity }: { activity: TransactionHistory["activity"] }) {
  return <section className="grid grid-cols-1 xl:grid-cols-2 gap-4 mb-6">
    <div className="card min-w-0">
      <p className="text-sm font-medium">Transaction frequency</p>
      <p className="text-xs text-text-secondary mt-1">Daily transaction counts from the same tenant, user, dataset, and lookback window.</p>
      {activity.daily_counts.length < 2 ? <p className="py-8 text-sm text-text-secondary">Not enough dated activity to compare frequency.</p> : <div className="mt-3 h-56">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={activity.daily_counts} margin={{ top: 8, right: 12, bottom: 4, left: -18 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="date" tick={{ fill: "#CBD5E1", fontSize: 10 }} tickFormatter={(date) => date.slice(5)} interval="preserveStartEnd" />
            <YAxis allowDecimals={false} tick={{ fill: "#CBD5E1", fontSize: 10 }} />
            <Tooltip contentStyle={{ background: "#1E293B", border: "1px solid #334155" }} labelFormatter={(date) => `Date: ${date}`} />
            <Line type="monotone" dataKey="count" name="Transactions" stroke="#F59E0B" strokeWidth={2} activeDot={{ r: 5 }} dot={(props) => props.payload?.contains_incident ? <circle cx={props.cx} cy={props.cy} r={6} fill="#F59E0B" stroke="#fff" strokeWidth={2} /> : <g />} />
          </LineChart>
        </ResponsiveContainer>
      </div>}
      <p className="mt-2 text-xs text-gold">Highlighted point marks the incident date.</p>
    </div>
    <div className="card min-w-0">
      <p className="text-sm font-medium">24-hour transaction velocity</p>
      <p className="text-xs text-text-secondary mt-1">Rolling same-user transaction count at each recorded transaction, including the selected incident.</p>
      {activity.velocity_24h_series.length < 2 ? <p className="py-8 text-sm text-text-secondary">Not enough dated activity to show velocity.</p> : <div className="mt-3 h-56">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={activity.velocity_24h_series} margin={{ top: 8, right: 12, bottom: 4, left: -18 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="timestamp" tick={{ fill: "#CBD5E1", fontSize: 10 }} tickFormatter={(stamp) => stamp ? formatDate(stamp) : "—"} interval="preserveStartEnd" />
            <YAxis allowDecimals={false} tick={{ fill: "#CBD5E1", fontSize: 10 }} />
            <Tooltip contentStyle={{ background: "#1E293B", border: "1px solid #334155" }} labelFormatter={(stamp) => stamp ? new Date(stamp).toLocaleString() : "Unknown date"} />
            <Line type="monotone" dataKey="count" name="Transactions in trailing 24h" stroke="#60A5FA" strokeWidth={2} activeDot={{ r: 5 }} dot={(props) => props.payload?.is_incident ? <circle cx={props.cx} cy={props.cy} r={6} fill="#F59E0B" stroke="#fff" strokeWidth={2} /> : <g />} />
          </LineChart>
        </ResponsiveContainer>
      </div>}
      <p className="mt-2 text-xs text-gold">Highlighted point marks the incident transaction.</p>
    </div>
  </section>;
}

function GeographicComparison({ baseline, finding }: { baseline: TransactionHistory["baseline"]; finding?: TransactionHistory["findings"][number] }) {
  const locations = baseline.typical_locations;
  return <section className="card mb-6">
    <div className="flex flex-wrap justify-between gap-3 mb-4">
      <div><p className="text-sm font-medium">Geographic comparison</p><p className="text-xs text-text-secondary mt-1">Observed origins are compared with the same user&apos;s prior locations in this dataset.</p></div>
      <span className={`rounded-full border px-3 py-1 text-xs ${finding?.status === "location_change" ? "border-danger/40 bg-danger/10 text-danger" : "border-border text-text-secondary"}`}>{finding?.status?.replaceAll("_", " ") || "Not comparable"}</span>
    </div>
    <div className="grid grid-cols-1 md:grid-cols-2 gap-5 items-center">
      <div className="h-48">
        {locations.length ? <ResponsiveContainer width="100%" height="100%">
          <BarChart data={locations} layout="vertical" margin={{ top: 4, right: 16, bottom: 4, left: 8 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis type="number" allowDecimals={false} tick={{ fill: "#CBD5E1", fontSize: 10 }} />
            <YAxis type="category" dataKey="location" width={110} tick={{ fill: "#CBD5E1", fontSize: 10 }} />
            <Tooltip contentStyle={{ background: "#1E293B", border: "1px solid #334155" }} />
            <Bar dataKey="count" name="Historical transactions" fill="#60A5FA" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer> : <p className="py-8 text-sm text-text-secondary">No historical origin data was supplied.</p>}
      </div>
      <div className="rounded-lg border border-border/60 bg-background/40 p-4">
        <p className="text-[11px] uppercase tracking-wide text-text-secondary">Historical origin</p>
        <p className="mt-1 text-sm font-semibold">{locations.map((item) => item.location).join(", ") || "Not supplied"}</p>
        <p className="text-[11px] uppercase tracking-wide text-text-secondary mt-4">Current origin</p>
        <p className={`mt-1 text-sm font-semibold ${finding?.status === "location_change" ? "text-danger" : ""}`}>{baseline.current_location || "Not supplied"}</p>
        <p className="mt-3 text-xs text-text-secondary">{finding?.summary || "A location comparison is unavailable because one or both sides have no recorded origin."}</p>
      </div>
    </div>
  </section>;
}

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const searchParams = useSearchParams();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [evidence, setEvidence] = useState<any[]>([]);
  const [mapping, setMapping] = useState<MappingExplanation | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [history, setHistory] = useState<TransactionHistory | null>(null);
  const [historyError, setHistoryError] = useState("");
  const [profileOpen, setProfileOpen] = useState(searchParams.get("profile") === "1");

  function load() {
    apiFetch<Incident>(`/incidents/${id}`).then(setIncident).catch(() => {});
  }

  useEffect(load, [id]);

  useEffect(() => {
    setHistory(null);
    setHistoryError("");
    apiFetch<TransactionHistory>(`/incidents/${id}/history?lookback_days=90`)
      .then(setHistory)
      .catch((error) => setHistoryError(error instanceof Error ? error.message : "Unable to load transaction history."));
    apiFetch<{ evidence: typeof evidence }>(`/incidents/${id}/evidence`)
      .then((r) => setEvidence(r.evidence))
      .catch(() => {});
    apiFetch<MappingExplanation>(`/incidents/${id}/mapping-explanation`)
      .then(setMapping)
      .catch(() => {});
  }, [id]);

  async function analyze() {
    setAnalyzing(true);
    try {
      const updated = await apiFetch<Incident>(`/incidents/${id}/analyze`, { method: "POST" });
      setIncident(updated);
      // Refresh evidence and mapping after analysis
      apiFetch<{ evidence: typeof evidence }>(`/incidents/${id}/evidence`)
        .then((r) => setEvidence(r.evidence))
        .catch(() => {});
      apiFetch<MappingExplanation>(`/incidents/${id}/mapping-explanation`)
        .then(setMapping)
        .catch(() => {});
    } finally {
      setAnalyzing(false);
    }
  }

  async function feedback(label: "false_positive" | "true_positive") {
    await apiFetch(`/incidents/${id}/feedback`, {
      method: "POST",
      body: JSON.stringify({ label }),
    });
    load();
  }

  if (!incident) return <p className="text-text-secondary">Loading…</p>;

  const validation = incident.analysis_json?.validation;
  const mitreMappings = (incident.analysis_json?.mitre || []).filter(
    (mapping) => mapping.status === "evidence_backed" && Boolean(mapping.supporting_evidence?.length)
  );
  const nistMappings = (incident.analysis_json?.nist || []).filter(
    (mapping) => mapping.status === "evidence_backed" && Boolean(mapping.supporting_evidence?.length)
  );
  const confidencePercent = incident.confidence != null ? `${(incident.confidence * 100).toFixed(0)}%` : "n/a";
  const coveragePercent = incident.evidence_coverage != null ? `${Math.round(incident.evidence_coverage * 100)}%` : "n/a";
  const statusTone = incident.analysis_json?.intelligence_status?.toLowerCase() === "validated"
    ? "border-success/40 bg-success/10 text-success"
    : incident.analysis_json?.intelligence_status?.toLowerCase() === "failed"
      ? "border-danger/40 bg-danger/10 text-danger"
      : "border-gold/40 bg-gold/10 text-gold";

  return (
    <div className="max-w-6xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold">{incident.id}</h1>
          <button onClick={() => setProfileOpen((open) => !open)} className="text-sm text-gold hover:underline">
            {incident.user_id} · {profileOpen ? "Hide account profile" : "View account profile"}
          </button>
        </div>
        <RiskBadge score={incident.risk_score} />
      </div>

      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="card">
          <p className="text-xs text-text-secondary">Amount</p>
          <p className="text-lg font-medium">${incident.amount.toLocaleString()}</p>
        </div>
        <div className="card">
          <p className="text-xs text-text-secondary">Anomaly score</p>
          <p className="text-lg font-medium">{incident.anomaly_score.toFixed(3)}</p>
        </div>
        <div className="card">
          <p className="text-xs text-text-secondary">Confidence</p>
          <p className="text-lg font-medium">{incident.confidence?.toFixed(2) ?? "—"}</p>
        </div>
      </div>

      <section className="card mb-6">
        <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
          <div>
            <p className="text-sm font-medium">Investigation overview</p>
            <p className="text-xs text-text-secondary mt-1">Incident scores remain separate from historical comparison signals.</p>
          </div>
          <span className="rounded-full border border-border px-3 py-1 text-xs">
            {history?.dataset_source === "DEMO" ? "Demo" : history?.dataset_source === "USER_TEST" ? "User test" : history?.dataset_source === "TENANT" ? "Tenant dataset" : incident.dataset_source || "Provenance unavailable"}
          </span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            ["Risk score", incident.risk_score.toFixed(2)],
            ["Anomaly score", incident.anomaly_score.toFixed(2)],
            ["Evidence coverage", coveragePercent],
            ["Investigation confidence", confidencePercent],
            ["Investigation status", incident.analysis_json?.intelligence_status || "Pending"],
            ["Related historical transactions", history ? String(history.historical_transaction_count) : "—"],
            ["Lookback period", history ? `${history.lookback_days} days` : "—"],
            ["Dataset ID", history?.dataset_id || incident.dataset_id || "Unavailable"],
          ].map(([label, value]) => (
            <div key={label} className="rounded-lg border border-border/60 bg-background/40 p-3">
              <p className="text-[11px] uppercase tracking-wide text-text-secondary">{label}</p>
              <p className="mt-1 text-sm font-semibold break-words">{value}</p>
            </div>
          ))}
        </div>
      </section>

      {profileOpen && history && (
        <section className="card mb-6">
          <p className="text-sm font-medium mb-1">User / account profile</p>
          <p className="text-xs text-text-secondary mb-4">Profile fields are derived from rows in this tenant and active dataset; absent fields are not inferred.</p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
            <ProfileValue label="Name" value={history.profile.account_name} />
            <ProfileValue label="Account age" value={history.profile.account_age_days != null ? `${history.profile.account_age_days} days` : null} />
            <ProfileValue label="Transactions in lookback" value={history.profile.transaction_count} />
            <ProfileValue label="Transaction volume" value={formatMoney(history.profile.transaction_volume, history.transactions.find((row) => row.currency)?.currency)} />
            <ProfileValue label="Average transaction" value={history.profile.average_transaction != null ? formatMoney(history.profile.average_transaction, history.transactions.find((row) => row.currency)?.currency) : null} />
            <ProfileValue label="Source accounts" value={history.profile.source_accounts.join(", ")} />
            <ProfileValue label="Devices" value={history.profile.devices.join(", ")} />
            <ProfileValue label="Known IPs" value={history.profile.known_ips.join(", ")} />
            <ProfileValue label="Transaction types" value={formatCounts(history.profile.transaction_types)} />
            <ProfileValue label="Channels" value={formatCounts(history.profile.channels)} />
            <ProfileValue label="Typical locations" value={history.profile.typical_locations.map((item) => item.location).join(", ")} />
          </div>
          <ProfileRiskTrend rows={history.transactions} />
        </section>
      )}

      <div className="card mb-6">
        <div className="flex items-center justify-between mb-3">
          <p className="text-sm font-medium">Intelligence analysis</p>
          <button onClick={analyze} disabled={analyzing} className="btn-primary text-xs">
            {analyzing ? "Analyzing…" : incident.explanation ? "Re-analyze" : "Run analysis"}
          </button>
        </div>
        <p className="text-sm text-text-secondary mb-2">
          {incident.explanation || "No analysis run yet."}
        </p>
        {incident.limitations && (
          <p className="text-xs text-text-secondary italic">{incident.limitations}</p>
        )}
      </div>

      <div className="card mb-6">
        <div className="flex items-center justify-between mb-3">
          <p className="text-sm font-medium">Investigation metadata</p>
          <div className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium ${statusTone}`}>
            {incident.analysis_json?.intelligence_status || "Pending"}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
          <div className="rounded-lg border border-border/60 bg-background/40 p-3">
            <p className="text-[11px] uppercase tracking-wide text-text-secondary mb-1">Evidence confidence</p>
            <p className="text-lg font-semibold">{confidencePercent}</p>
            <p className="text-xs text-text-secondary">Coverage {coveragePercent}</p>
          </div>
          <div className="rounded-lg border border-border/60 bg-background/40 p-3">
            <p className="text-[11px] uppercase tracking-wide text-text-secondary mb-1">Validation</p>
            <div className="flex flex-wrap gap-2">
              <span className="rounded-full border border-success/30 bg-success/10 px-2 py-1 text-xs text-success">
                Schema {validation?.schema_valid ? "✓" : "•"}
              </span>
              <span className="rounded-full border border-success/30 bg-success/10 px-2 py-1 text-xs text-success">
                Grounded {validation?.evidence_grounded ? "✓" : "•"}
              </span>
              <span className="rounded-full border border-success/30 bg-success/10 px-2 py-1 text-xs text-success">
                Tenant {validation?.tenant_scope_valid ? "✓" : "•"}
              </span>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-xs text-text-secondary uppercase mb-1">Model provenance</p>
            <p className="font-medium">
              {incident.risk_score_source === "model" && incident.model_version
                ? `FinSecAI model • ${incident.model_version}`
                : incident.risk_score_source === "uploaded"
                  ? "Uploaded dataset"
                  : "Not recorded"}
            </p>
          </div>
          <div>
            <p className="text-xs text-text-secondary uppercase mb-1">LLM provider</p>
            <p className="font-medium">{incident.analysis_json?.llm_provider || incident.analysis_json?.llm_provider_error || incident.analysis_json?.validation?.status || "Unavailable"}</p>
          </div>
          <div>
            <p className="text-xs text-text-secondary uppercase mb-1">Retrieval method</p>
            <p className="font-medium">{incident.analysis_json?.retrieval_method || incident.analysis_json?.validation?.status || "Unavailable"}</p>
          </div>
          <div>
            <p className="text-xs text-text-secondary uppercase mb-1">Embedding model</p>
            <p className="font-medium">{incident.analysis_json?.embedding_model || evidence[0]?.metadata?.embedding_model || "Unavailable"}</p>
          </div>
        </div>
      </div>

      <div className="card mb-6">
        <p className="text-sm font-medium mb-2">Framework mapping</p>
        {mapping && <p className="text-xs text-text-secondary mb-3">{Array.isArray(mapping.rationale) ? mapping.rationale.join(" ") : mapping.rationale}</p>}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="text-xs text-text-secondary uppercase mb-1">MITRE ATT&amp;CK</p>
            {mitreMappings.length === 0 && <p className="text-sm text-text-secondary">No evidence-backed mappings are available.</p>}
            {mitreMappings.map((m: any) => {
              const id = m.id || m;
              const name = m.name || m.id || "";
              const badge = m.status === "evidence_backed" ? "Evidence-backed" : "Candidate";
              const tone = badge === "Evidence-backed" ? "text-success" : "text-gold";
              return (
                <div key={id} className="mb-2">
                  <p className="text-sm">
                    <span className="text-gold font-mono">{id}</span> — {name}
                  </p>
                  <div className="mt-1">
                    <span className={`rounded-full border px-2 py-1 text-xs ${tone}`}>{badge}</span>
                  </div>
                </div>
              );
            })}
          </div>
          <div>
            <p className="text-xs text-text-secondary uppercase mb-1">NIST controls</p>
            {nistMappings.length === 0 && <p className="text-sm text-text-secondary">No evidence-backed mappings are available.</p>}
            {nistMappings.map((c: any) => {
              const id = c.id || c;
              const name = c.name || c.id || "";
              const badge = c.status === "evidence_backed" ? "Evidence-backed" : "Candidate";
              const tone = badge === "Evidence-backed" ? "text-success" : "text-gold";
              return (
                <div key={id} className="mb-2">
                  <p className="text-sm">
                    <span className="text-gold font-mono">{id}</span> — {name}
                  </p>
                  <div className="mt-1">
                    <span className={`rounded-full border px-2 py-1 text-xs ${tone}`}>{badge}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="card mb-6">
        <p className="text-sm font-medium mb-2">Evidence used ({evidence.length})</p>
        {evidence.length === 0 && (
          <p className="text-sm text-text-secondary">
            No evidence chunks are tagged for this risk tier yet — this reflects the evidence store's current contents, not an analysis failure. Confidence and the explanation above are generated independently of evidence count.
          </p>
        )}
        {evidence.map((e, i) => (
          <div key={i} className="border-t border-border/50 pt-2 mt-2 first:border-0 first:pt-0 first:mt-0">
            <div className="flex items-center justify-between">
              <p className="text-xs text-gold font-mono">{e.framework_id}</p>
              <p className="text-xs text-text-secondary">Source: {e.source || (e.metadata && e.metadata.source) || 'unknown'}</p>
            </div>
            <p className="text-sm text-text-secondary">{e.text}</p>
            <p className="text-xs text-text-secondary mt-1">Similarity: {e.similarity != null ? `${(e.similarity * 100).toFixed(1)}%` : 'n/a'} • Embedding: {e.metadata?.embedding_model || 'n/a'}</p>
          </div>
        ))}
      </div>

      <section className="card mb-6">
        <div className="flex flex-wrap justify-between items-start gap-2 mb-4">
          <div>
            <p className="text-sm font-medium">Transaction timeline</p>
            <p className="text-xs text-text-secondary mt-1">
              {history ? `${history.historical_transaction_count} prior same-user transactions in the ${history.lookback_days}-day window, plus this incident.` : "Loading same-user history…"}
            </p>
          </div>
          <div className="flex items-center gap-3">
            {history?.truncated && <span className="text-xs text-gold">Showing the most recent 5,000 matching rows.</span>}
            {history && <button onClick={() => downloadEvidenceCsv(history, incident.analysis_json?.findings || [], evidence, validation)} className="text-xs text-gold hover:underline">Export evidence CSV</button>}
          </div>
        </div>
        {historyError && <p className="text-sm text-danger">Historical evidence unavailable: {historyError}</p>}
        {history && history.transactions.length === 1 && <p className="text-sm text-text-secondary">No related transactions were found in this dataset and lookback window. Comparisons will remain limited rather than inferred.</p>}
        {history && history.transactions.length > 1 && (
          <>
            <TimelineRail rows={history.transactions} />
            <div className="overflow-x-auto mt-4">
              <table className="w-full text-xs min-w-[760px]">
                <thead><tr className="text-left text-text-secondary border-b border-border"><th className="py-2 pr-3">Date</th><th className="py-2 pr-3">Transaction</th><th className="py-2 pr-3">Amount</th><th className="py-2 pr-3">Type / channel</th><th className="py-2 pr-3">Origin</th><th className="py-2 pr-3">Risk / anomaly</th></tr></thead>
                <tbody>{history.transactions.map((row) => <tr key={row.incident_id} className={`border-b border-border/40 ${row.is_incident ? "bg-gold/10" : ""}`}>
                  <td className="py-2 pr-3 whitespace-nowrap">{formatDate(row.timestamp)}</td>
                  <td className="py-2 pr-3 font-mono">{row.transaction_id}{row.is_incident && <span className="ml-2 text-gold">INCIDENT</span>}</td>
                  <td className="py-2 pr-3 whitespace-nowrap">{formatMoney(row.amount, row.currency)}</td>
                  <td className="py-2 pr-3">{row.transaction_type}{row.channel ? ` / ${row.channel}` : ""}</td>
                  <td className="py-2 pr-3">{row.location || "Not supplied"}</td>
                  <td className="py-2 pr-3">{row.risk_score.toFixed(2)} / {row.anomaly_score.toFixed(2)}</td>
                </tr>)}</tbody>
              </table>
            </div>
          </>
        )}
      </section>

      {history && <>
        <section className="card mb-6">
          <p className="text-sm font-medium mb-1">User historical baseline</p>
          <p className="text-xs text-text-secondary mb-4">Comparisons use the incident&apos;s own dataset and transactions before its timestamp.</p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm min-w-[520px]">
              <thead><tr className="text-left text-text-secondary border-b border-border"><th className="py-2 pr-3">Metric</th><th className="py-2 pr-3">Historical</th><th className="py-2 pr-3">Current</th><th className="py-2 pr-3">Comparison</th></tr></thead>
              <tbody>
                <BaselineRow label="Transactions in lookback" historical={`${history.historical_transaction_count} prior transactions`} current="1 incident" comparison={`${history.lookback_days}-day window`} />
                <BaselineRow label={`${history.baseline.transaction_type} count`} historical={`${history.baseline.comparable_transaction_count} prior`} current="1 incident" comparison={history.baseline.comparable_transaction_count >= 3 ? `${history.baseline.similar_transactions.length} examples shown` : "Limited history"} />
                <BaselineRow label={`${history.baseline.transaction_type} amount`} historical={history.baseline.average_amount != null ? formatMoney(history.baseline.average_amount, history.transactions.find((row) => row.currency)?.currency) : "No prior match"} current={formatMoney(incident.amount, history.transactions.find((row) => row.is_incident)?.currency)} comparison={history.baseline.amount_variance_percent != null ? `${history.baseline.amount_variance_percent > 0 ? "+" : ""}${history.baseline.amount_variance_percent.toFixed(1)}% vs mean` : "Insufficient history"} />
                <BaselineRow label="Historical channel usage" historical={Object.entries(history.baseline.channel_usage).map(([channel, usage]) => `${channel} ${usage.percent ?? 0}% (${usage.count})`).join(", ") || "No channel history"} current={history.baseline.current_channel || "Not supplied"} comparison={history.baseline.current_channel_percent != null ? `${history.baseline.current_channel_percent.toFixed(1)}% of prior channel records` : "Not comparable"} />
                <BaselineRow label="Typical origin" historical={history.baseline.typical_locations.map((item) => item.location).join(", ") || "No location history"} current={history.baseline.current_location || "Not supplied"} comparison={history.findings.find((item) => item.finding.includes("origin"))?.status.replaceAll("_", " ") || "Not comparable"} />
                <BaselineRow label="Prior 24-hour activity" historical="Prior same-user rows" current={`${history.baseline.velocity_24h} related transactions`} comparison="Dataset-scoped count" />
              </tbody>
            </table>
          </div>
          {history.baseline.comparable_transaction_count < 3 && <p className="text-xs text-gold mt-3">A baseline needs more same-type history. The UI does not claim the transaction is typical without enough observations.</p>}
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-2 gap-4 mb-6">
          <TrendCard title="Risk and anomaly over time" subtitle="Persisted row scores; highlighted marker is the selected incident." rows={history.transactions} value="risk_score" secondary="anomaly_score" />
          <TrendCard title="Transaction amount over time" subtitle="Amounts are shown as uploaded; currency can vary across rows." rows={history.transactions} value="amount" />
        </section>

        <ActivityAnalytics activity={history.activity} />
        <GeographicComparison
          baseline={history.baseline}
          finding={history.findings.find((item) => item.finding.toLowerCase().includes("origin"))}
        />

        <section className="card mb-6">
          <p className="text-sm font-medium mb-1">Evidence explorer</p>
          <p className="text-xs text-text-secondary mb-4">Historical comparisons below link directly to transaction rows. They are behavioral signals, not fraud determinations.</p>
          <div className="space-y-4">
            {(incident.analysis_json?.findings || []).map((finding, index) => {
              const citedIds = finding.supporting_evidence || [];
              const citedEvidence = citedIds.map((evidenceId: string) => evidence.find((item) => String(item.evidence_id) === evidenceId)).filter(Boolean);
              return <div key={`ai-finding-${index}`} className="rounded-lg border border-gold/30 bg-gold/5 p-3">
                <div className="flex flex-wrap justify-between gap-2"><p className="text-sm font-medium">Investigation finding: {finding.finding}</p><span className="text-xs text-gold">{finding.severity || "unrated"} · {finding.confidence != null ? `${Math.round(finding.confidence * 100)}% confidence` : "confidence unavailable"}</span></div>
                <p className="text-sm text-text-secondary mt-1">{finding.rationale || finding.observed_signal || "No additional rationale was persisted."}</p>
                {citedEvidence.length > 0 ? <div className="mt-3 space-y-2">{citedEvidence.map((item: any) => <div key={item.evidence_id} className="rounded border border-border/60 p-2"><p className="text-xs text-gold font-mono">Retrieved record · {item.evidence_id} · {item.framework_id || item.source || "Reference"}</p><p className="text-sm text-text-secondary mt-1">{item.text}</p></div>)}</div> : <p className="mt-2 text-xs text-text-secondary">{citedIds.length ? `Cited evidence IDs were not present in the current retrieval response: ${citedIds.join(", ")}` : "No retrieved record IDs were linked to this finding; review as an unlinked narrative, not a record-backed conclusion."}</p>}
              </div>;
            })}
            {history.findings.map((finding) => {
              const evidenceRows = finding.supporting_transaction_ids.map((transactionId) => history.transactions.find((row) => row.transaction_id === transactionId)).filter((row): row is HistoricalTransaction => Boolean(row));
              return <div key={finding.finding} className="rounded-lg border border-border/60 p-3">
                <div className="flex flex-wrap justify-between gap-2"><p className="text-sm font-medium">Finding: {finding.finding}</p><span className="text-xs text-gold">{finding.status.replaceAll("_", " ")}</span></div>
                <p className="text-sm text-text-secondary mt-1">{finding.summary}</p>
                {evidenceRows.length > 0 ? <div className="overflow-x-auto mt-3"><table className="w-full text-xs min-w-[560px]"><thead><tr className="text-left text-text-secondary border-b border-border"><th className="py-1 pr-2">Supporting transaction</th><th className="py-1 pr-2">Date</th><th className="py-1 pr-2">Amount</th><th className="py-1 pr-2">Type / channel</th><th className="py-1 pr-2">Origin</th></tr></thead><tbody>{evidenceRows.map((row) => <tr key={row.incident_id} className="border-b border-border/40"><td className="py-2 pr-2 font-mono">{row.transaction_id}</td><td className="py-2 pr-2">{formatDate(row.timestamp)}</td><td className="py-2 pr-2">{formatMoney(row.amount, row.currency)}</td><td className="py-2 pr-2">{row.transaction_type} / {row.channel || "Not supplied"}</td><td className="py-2 pr-2">{row.location || "Not supplied"}</td></tr>)}</tbody></table></div> : <p className="text-xs text-text-secondary mt-2">No supporting historical transaction rows are available for this comparison.</p>}
              </div>;
            })}
            {evidence.map((item, index) => <div key={`${item.framework_id}-${index}`} className="rounded-lg border border-border/60 p-3">
              <p className="text-xs text-gold">Retrieved reference evidence · {item.framework_id || item.source || "Reference"}</p>
              <p className="text-sm text-text-secondary mt-1">{item.text}</p>
            </div>)}
          </div>
        </section>

        <section className="card mb-6">
          <p className="text-sm font-medium mb-3">Investigation evidence chain</p>
          <ol className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-2 text-xs">
            {["Incident record", `User ${incident.user_id}`, `${history.lookback_days}-day dataset history (${history.historical_transaction_count} prior)`, "Historical baseline and current comparison", `Retrieved evidence (${evidence.length} records)`, "AI / rule-based investigation", `Validation: ${validation?.status || incident.analysis_json?.intelligence_status || "pending"}`, incident.explanation ? `Final finding: ${incident.explanation}` : "Final finding pending analysis", "Analyst review"].map((step, index) => <li key={step} className="rounded-lg border border-border/60 p-3"><span className="text-gold font-mono">{String(index + 1).padStart(2, "0")}</span><p className="mt-1">{step}</p></li>)}
          </ol>
        </section>
      </>}

      {incident.governance_flags && (
        <div className="card mb-6 border-danger/40">
          <p className="text-sm font-medium mb-2 text-danger">Governance flags</p>
          <p className="text-sm text-text-secondary">{incident.governance_flags}</p>
        </div>
      )}

      <div className="flex gap-3">
        <button onClick={() => feedback("false_positive")} className="border border-border rounded-lg px-4 py-2 text-sm hover:border-success hover:text-success">
          Mark false positive
        </button>
        <button onClick={() => feedback("true_positive")} className="border border-border rounded-lg px-4 py-2 text-sm hover:border-danger hover:text-danger">
          Mark true positive
        </button>
        {incident.analysis_json ? (
          <button onClick={() => downloadReport(incident.id)} className="btn-primary text-sm ml-auto">
            Download PDF report
          </button>
        ) : (
          <button onClick={analyze} disabled={analyzing} className="btn-primary text-sm ml-auto">
            {analyzing ? "Analyzing…" : "Run analysis to generate report"}
          </button>
        )}
      </div>
    </div>
  );
}
