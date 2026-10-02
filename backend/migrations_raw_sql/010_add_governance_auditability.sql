-- Governance and auditability layer.
-- Every governance control is versioned through its parent document.
-- Tenant-scoped documents belong to a specific tenant.
-- Global documents (CBN/frameworks) use tenant_id NULL.
-- No existing incidents, evidence, or findings are modified.

CREATE TABLE IF NOT EXISTS governance_documents (
    id VARCHAR PRIMARY KEY,
    tenant_id VARCHAR NULL REFERENCES tenants(id),
    document_type VARCHAR NOT NULL,
    name VARCHAR NOT NULL,
    version VARCHAR NOT NULL,
    issuer VARCHAR NOT NULL DEFAULT '',
    effective_date TIMESTAMP NULL,
    source VARCHAR NOT NULL DEFAULT '',
    dataset_source VARCHAR NULL,
    dataset_id VARCHAR NULL,
    status VARCHAR NOT NULL DEFAULT 'ACTIVE',
    metadata_json JSON NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_governance_documents_tenant_id
    ON governance_documents(tenant_id);

CREATE INDEX IF NOT EXISTS ix_governance_documents_type
    ON governance_documents(document_type);

CREATE INDEX IF NOT EXISTS ix_governance_documents_status
    ON governance_documents(status);


CREATE TABLE IF NOT EXISTS governance_controls (
    id VARCHAR PRIMARY KEY,
    governance_document_id VARCHAR NOT NULL
        REFERENCES governance_documents(id),
    control_id VARCHAR NOT NULL,
    title VARCHAR NOT NULL DEFAULT '',
    control_text TEXT NOT NULL DEFAULT '',
    control_type VARCHAR NOT NULL,
    framework VARCHAR NULL,
    parent_control_id VARCHAR NULL,
    metadata_json JSON NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_governance_controls_document_id
    ON governance_controls(governance_document_id);

CREATE INDEX IF NOT EXISTS ix_governance_controls_control_id
    ON governance_controls(control_id);


CREATE TABLE IF NOT EXISTS finding_governance_links (
    id VARCHAR PRIMARY KEY,
    incident_id VARCHAR NOT NULL
        REFERENCES incidents(id),
    finding_id VARCHAR NOT NULL,
    control_id VARCHAR NOT NULL
        REFERENCES governance_controls(id),
    relationship_type VARCHAR NOT NULL,
    match_reason TEXT NOT NULL DEFAULT '',
    supporting_evidence JSON NOT NULL DEFAULT '[]',
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    validation_status VARCHAR NOT NULL DEFAULT 'candidate',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_finding_governance_links_incident_id
    ON finding_governance_links(incident_id);

CREATE INDEX IF NOT EXISTS ix_finding_governance_links_finding_id
    ON finding_governance_links(finding_id);

CREATE INDEX IF NOT EXISTS ix_finding_governance_links_control_id
    ON finding_governance_links(control_id);

CREATE INDEX IF NOT EXISTS ix_finding_governance_links_relationship
    ON finding_governance_links(relationship_type);
