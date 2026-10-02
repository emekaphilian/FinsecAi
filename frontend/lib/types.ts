export interface InvestigationValidation {
  schema_valid?: boolean;
  evidence_grounded?: boolean;
  frameworks_grounded?: boolean;
  tenant_scope_valid?: boolean;
  status?: string;
}

export interface InvestigationAnalysisJson {
  intelligence_status?: string;
  llm_provider?: string;
  llm_provider_error?: string;
  llm_model?: string;
  retrieval_method?: string;
  embedding_model?: string;
  validation?: InvestigationValidation;
  evidence?: Array<any>;
  findings?: Array<{ finding: string; severity: string; observed_signal: string; rationale: string; supporting_evidence?: string[]; confidence?: number }>;
  mitre?: Array<{ id: string; name?: string; rationale?: string; source?: string; status?: "evidence_backed" | "candidate"; basis?: string; supporting_evidence?: string[]; confidence?: number }>;
  nist?: Array<{ id: string; name?: string; rationale?: string; source?: string; status?: "evidence_backed" | "candidate"; basis?: string; supporting_evidence?: string[]; confidence?: number }>;
}

export interface Incident {
  id: string;
  tenant_id: string;
  user_id: string;
  amount: number;
  transaction_type: string;
  device_id: string;
  risk_score: number;
  anomaly_score: number;
  created_at: string;
  dataset_source?: string | null;
  dataset_id?: string | null;
  dataset_name?: string | null;
  dataset_version?: string | null;
  dataset_record_count?: number | null;
  confidence?: number | null;
  evidence_coverage?: number | null;
  explanation?: string | null;
  limitations?: string | null;
  governance_flags?: string | null;
  mitre_techniques?: string | null;
  nist_controls?: string | null;
  analysis_json?: InvestigationAnalysisJson | null;
  risk_score_source?: string | null;
  anomaly_score_source?: string | null;
  model_version?: string | null;
}

export interface AnalyticsSummary {
  total_incidents: number;
  analyzed_count: number;
  avg_risk: number;
  avg_confidence: number;
  high_risk_count: number;
  governance_flags_count: number;
}

export interface PrecisionRecall {
  precision: number;
  recall: number;
  f1: number;
  true_positives: number;
  false_positives: number;
  false_negatives?: number;
  true_negatives?: number;
}

export interface DriftResult {
  drift_score: number;
  status: string;
}

export interface AuthSession {
  role: string;
  tenant_id: string | null;
}

export interface Tenant {
  id: string;
  name: string;
  description: string;
  tenant_type: string | null;
  provenance: string;
  status: string;
  industry: string;
  website: string;
  contact_email: string;
  contact_phone: string;
  country: string;
  timezone: string;
  created_at: string;
  updated_at: string;
  user_count: number;
  incident_count: number;
  evidence_count: number;
  report_count: number;
  configured: boolean;
}

export interface EnterpriseSummary {
  total_tenants: number;
  active_customer_tenants: number;
  demo_tenants: number;
  total_incidents: number;
  high_risk_incidents: number;
  reports_generated: number;
}
