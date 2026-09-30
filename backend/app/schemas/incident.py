from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class IncidentOut(BaseModel):
    model_config = {"protected_namespaces": ()}
    id: str
    tenant_id: str
    user_id: str
    amount: float
    transaction_type: str = "TRANSFER"
    device_id: str = ""
    risk_score: float
    anomaly_score: float
    created_at: datetime
    confidence: Optional[float] = None
    evidence_coverage: Optional[float] = None
    explanation: Optional[str] = None
    limitations: Optional[str] = None
    governance_flags: Optional[str] = None
    mitre_techniques: Optional[str] = None
    nist_controls: Optional[str] = None
    analysis_json: Optional[dict] = None
    risk_score_source: str = "uploaded"
    anomaly_score_source: str = "uploaded"
    model_version: Optional[str] = None
    dataset_source: Optional[str] = None
    dataset_id: Optional[str] = None
    dataset_name: Optional[str] = None
    dataset_version: Optional[str] = None
    dataset_record_count: Optional[int] = None


class FeedbackIn(BaseModel):
    label: str = Field(..., pattern="^(false_positive|true_positive)$")


class Token(BaseModel):
    access_token: str
    role: str
    tenant_id: Optional[str] = None
    email: str
    must_change_password: bool = False
    token_type: str = "bearer"
    refresh_token: Optional[str] = None


class CredentialChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=256)
    new_email: Optional[str] = Field(default=None, min_length=3, max_length=320)


class AnalyticsSummary(BaseModel):
    total_incidents: int
    analyzed_count: int
    avg_risk: float
    avg_confidence: float
    high_risk_count: int
    governance_flags_count: int


class EnterpriseSummary(BaseModel):
    total_tenants: int
    active_customer_tenants: int
    demo_tenants: int
    total_incidents: int
    high_risk_incidents: int
    reports_generated: int
