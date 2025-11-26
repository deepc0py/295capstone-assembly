-- ============================================================================
-- Auto-Init Script: Finding Triage Workflow
-- ============================================================================
-- Description: Docker container auto-initialization for triage tables
-- Week: 3
-- Priority: P0
-- ============================================================================

-- Connect to ventiapi database
\c ventiapi

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- Table: finding_triage
-- ============================================================================

CREATE TABLE IF NOT EXISTS finding_triage (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,

    -- Status tracking
    status TEXT NOT NULL DEFAULT 'new',
    previous_status TEXT,
    status_changed_at TIMESTAMP DEFAULT NOW(),
    status_changed_by TEXT,

    -- Assignment tracking
    assigned_to TEXT,
    assigned_at TIMESTAMP,
    assigned_by TEXT,

    -- Validation tracking
    validated_by TEXT,
    validated_at TIMESTAMP,
    validation_notes TEXT,

    -- SLA tracking
    sla_deadline TIMESTAMP,
    sla_days INTEGER,
    is_overdue BOOLEAN GENERATED ALWAYS AS (
        CASE
            WHEN sla_deadline IS NOT NULL AND sla_deadline < NOW() AND status NOT IN ('resolved', 'risk_accepted', 'false_positive')
            THEN true
            ELSE false
        END
    ) STORED,

    -- Risk acceptance
    risk_acceptance_reason TEXT,
    risk_accepted_by TEXT,
    risk_accepted_at TIMESTAMP,

    -- Metadata
    priority_override INTEGER CHECK (priority_override BETWEEN 0 AND 100),
    tags TEXT[],
    metadata JSONB DEFAULT '{}'::jsonb,

    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    -- Constraints
    CONSTRAINT finding_triage_finding_id_unique UNIQUE (finding_id),
    CONSTRAINT finding_triage_status_check CHECK (
        status IN ('new', 'validated', 'false_positive', 'duplicate', 'risk_accepted', 'in_progress', 'resolved', 'wont_fix')
    )
);

CREATE INDEX IF NOT EXISTS idx_finding_triage_finding_id ON finding_triage(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_triage_status ON finding_triage(status);
CREATE INDEX IF NOT EXISTS idx_finding_triage_assigned_to ON finding_triage(assigned_to);
CREATE INDEX IF NOT EXISTS idx_finding_triage_assigned_to_status ON finding_triage(assigned_to, status);
CREATE INDEX IF NOT EXISTS idx_finding_triage_sla_deadline ON finding_triage(sla_deadline) WHERE sla_deadline IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_finding_triage_overdue ON finding_triage(is_overdue) WHERE is_overdue = true;
CREATE INDEX IF NOT EXISTS idx_finding_triage_tags ON finding_triage USING GIN(tags);

-- ============================================================================
-- Table: finding_comments
-- ============================================================================

CREATE TABLE IF NOT EXISTS finding_comments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,

    -- Comment content
    author TEXT NOT NULL,
    comment TEXT NOT NULL,
    comment_type TEXT DEFAULT 'note',

    -- Metadata
    is_internal BOOLEAN DEFAULT false,
    mentions TEXT[],
    attachments JSONB DEFAULT '[]'::jsonb,

    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    edited_by TEXT,

    -- Constraints
    CONSTRAINT finding_comments_comment_type_check CHECK (
        comment_type IN ('note', 'analysis', 'remediation', 'escalation', 'resolution')
    )
);

CREATE INDEX IF NOT EXISTS idx_finding_comments_finding_id ON finding_comments(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_comments_author ON finding_comments(author);
CREATE INDEX IF NOT EXISTS idx_finding_comments_created_at ON finding_comments(finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_finding_comments_comment_type ON finding_comments(comment_type);

-- ============================================================================
-- Table: finding_status_history
-- ============================================================================

CREATE TABLE IF NOT EXISTS finding_status_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,

    -- Status change tracking
    old_status TEXT,
    new_status TEXT NOT NULL,
    changed_by TEXT NOT NULL,
    change_reason TEXT,

    -- Context
    assigned_to TEXT,
    sla_deadline TIMESTAMP,

    -- Timestamp
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_finding_status_history_finding_id ON finding_status_history(finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_finding_status_history_changed_by ON finding_status_history(changed_by);

-- ============================================================================
-- Helper Functions
-- ============================================================================

CREATE OR REPLACE FUNCTION update_finding_triage_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_finding_triage_timestamp ON finding_triage;
CREATE TRIGGER trigger_update_finding_triage_timestamp
    BEFORE UPDATE ON finding_triage
    FOR EACH ROW
    EXECUTE FUNCTION update_finding_triage_updated_at();

CREATE OR REPLACE FUNCTION record_finding_status_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM NEW.status THEN
        INSERT INTO finding_status_history (
            finding_id,
            old_status,
            new_status,
            changed_by,
            assigned_to,
            sla_deadline
        ) VALUES (
            NEW.finding_id,
            OLD.status,
            NEW.status,
            NEW.status_changed_by,
            NEW.assigned_to,
            NEW.sla_deadline
        );

        NEW.previous_status = OLD.status;
        NEW.status_changed_at = NOW();
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_record_status_change ON finding_triage;
CREATE TRIGGER trigger_record_status_change
    BEFORE UPDATE ON finding_triage
    FOR EACH ROW
    EXECUTE FUNCTION record_finding_status_change();

CREATE OR REPLACE FUNCTION calculate_sla_deadline(
    severity TEXT,
    custom_days INTEGER DEFAULT NULL
)
RETURNS TIMESTAMP AS $$
DECLARE
    sla_days INTEGER;
BEGIN
    IF custom_days IS NOT NULL THEN
        sla_days = custom_days;
    ELSE
        sla_days = CASE severity
            WHEN 'Critical' THEN 2
            WHEN 'High' THEN 7
            WHEN 'Medium' THEN 30
            WHEN 'Low' THEN 90
            ELSE 30
        END;
    END IF;

    RETURN NOW() + (sla_days || ' days')::INTERVAL;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Helper Views
-- ============================================================================

CREATE OR REPLACE VIEW triaged_findings AS
SELECT
    f.id,
    f.scan_id,
    f.rule,
    f.title,
    f.severity,
    f.score,
    f.endpoint,
    f.method,
    f.description,
    f.evidence,
    f.scanner,
    f.fingerprint,
    f.created_at AS finding_created_at,
    t.id AS triage_id,
    t.status,
    t.previous_status,
    t.status_changed_at,
    t.status_changed_by,
    t.assigned_to,
    t.assigned_at,
    t.assigned_by,
    t.validated_by,
    t.validated_at,
    t.sla_deadline,
    t.sla_days,
    t.is_overdue,
    t.priority_override,
    t.tags,
    t.created_at AS triage_created_at,
    t.updated_at AS triage_updated_at,
    CASE
        WHEN t.sla_deadline IS NOT NULL
        THEN EXTRACT(EPOCH FROM (t.sla_deadline - NOW())) / 86400
        ELSE NULL
    END AS days_until_sla,
    (SELECT COUNT(*) FROM finding_comments WHERE finding_id = f.id) AS comment_count
FROM findings f
LEFT JOIN finding_triage t ON f.id = t.finding_id;

CREATE OR REPLACE VIEW overdue_findings AS
SELECT
    tf.*,
    EXTRACT(EPOCH FROM (NOW() - tf.sla_deadline)) / 86400 AS days_overdue
FROM triaged_findings tf
WHERE tf.is_overdue = true
ORDER BY tf.sla_deadline ASC;

CREATE OR REPLACE VIEW assigned_findings_summary AS
SELECT
    assigned_to,
    status,
    COUNT(*) AS finding_count,
    COUNT(*) FILTER (WHERE is_overdue = true) AS overdue_count,
    AVG(EXTRACT(EPOCH FROM (sla_deadline - NOW())) / 86400) AS avg_days_until_sla
FROM finding_triage
WHERE assigned_to IS NOT NULL
GROUP BY assigned_to, status;

CREATE OR REPLACE VIEW triage_metrics AS
SELECT
    COUNT(*) AS total_triaged,
    COUNT(*) FILTER (WHERE status = 'new') AS new_count,
    COUNT(*) FILTER (WHERE status = 'validated') AS validated_count,
    COUNT(*) FILTER (WHERE status = 'false_positive') AS false_positive_count,
    COUNT(*) FILTER (WHERE status = 'in_progress') AS in_progress_count,
    COUNT(*) FILTER (WHERE status = 'resolved') AS resolved_count,
    COUNT(*) FILTER (WHERE is_overdue = true) AS overdue_count,
    COUNT(*) FILTER (WHERE assigned_to IS NOT NULL) AS assigned_count,
    AVG(EXTRACT(EPOCH FROM (sla_deadline - NOW())) / 86400) FILTER (WHERE sla_deadline IS NOT NULL) AS avg_days_until_sla,
    AVG(EXTRACT(EPOCH FROM (validated_at - created_at)) / 3600) FILTER (WHERE validated_at IS NOT NULL) AS avg_hours_to_validate,
    AVG(EXTRACT(EPOCH FROM (status_changed_at - created_at)) / 3600) FILTER (WHERE status = 'resolved') AS avg_hours_to_resolve
FROM finding_triage;
