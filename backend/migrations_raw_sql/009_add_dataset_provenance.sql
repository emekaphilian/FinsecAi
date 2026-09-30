-- Additive provenance migration: preserve all existing incidents and evidence.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS dataset_source VARCHAR;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS dataset_id VARCHAR;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS dataset_name VARCHAR;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS dataset_version VARCHAR;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS dataset_record_count INTEGER;

ALTER TABLE evidence_chunks ADD COLUMN IF NOT EXISTS dataset_source VARCHAR NOT NULL DEFAULT 'SHARED';
ALTER TABLE evidence_chunks ADD COLUMN IF NOT EXISTS dataset_id VARCHAR;

CREATE TABLE IF NOT EXISTS incident_datasets (
    id VARCHAR PRIMARY KEY,
    tenant_id VARCHAR REFERENCES tenants(id),
    source_type VARCHAR NOT NULL,
    name VARCHAR NOT NULL,
    version VARCHAR NOT NULL DEFAULT '1',
    record_count INTEGER NOT NULL DEFAULT 0,
    synthetic BOOLEAN NOT NULL DEFAULT FALSE,
    original_filename VARCHAR NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_incidents_dataset_source ON incidents(dataset_source);
CREATE INDEX IF NOT EXISTS ix_incidents_dataset_id ON incidents(dataset_id);
CREATE INDEX IF NOT EXISTS ix_evidence_chunks_dataset_source ON evidence_chunks(dataset_source);
CREATE INDEX IF NOT EXISTS ix_evidence_chunks_dataset_id ON evidence_chunks(dataset_id);
