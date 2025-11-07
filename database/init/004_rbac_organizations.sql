\c ventiapi

-- Migration 004: RBAC & Organization Isolation
-- Adds multi-tenant organization support with role-based access control

-- ============================================================================
-- 1. ORGANIZATIONS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL, -- URL-friendly identifier
    description TEXT,
    tier TEXT NOT NULL DEFAULT 'free', -- free, starter, professional, enterprise
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    CONSTRAINT organizations_tier_check CHECK (tier IN ('free', 'starter', 'professional', 'enterprise'))
);

CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);
CREATE INDEX IF NOT EXISTS idx_organizations_is_active ON organizations(is_active);

-- ============================================================================
-- 2. USERS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL,
    full_name TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    is_superuser BOOLEAN NOT NULL DEFAULT false, -- Platform admin (not org admin)
    email_verified BOOLEAN NOT NULL DEFAULT false,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP -- Soft delete
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);

-- ============================================================================
-- 3. ORGANIZATION MEMBERSHIPS (Users <-> Organizations)
-- ============================================================================

CREATE TABLE IF NOT EXISTS organization_memberships (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'viewer', -- admin, analyst, viewer
    invited_by UUID REFERENCES users(id),
    invited_at TIMESTAMP DEFAULT NOW(),
    joined_at TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    UNIQUE(organization_id, user_id),
    CONSTRAINT memberships_role_check CHECK (role IN ('admin', 'analyst', 'viewer'))
);

CREATE INDEX IF NOT EXISTS idx_memberships_org ON organization_memberships(organization_id);
CREATE INDEX IF NOT EXISTS idx_memberships_user ON organization_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_memberships_role ON organization_memberships(role);

-- ============================================================================
-- 4. ORGANIZATION SETTINGS
-- ============================================================================

CREATE TABLE IF NOT EXISTS organization_settings (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    max_scans_per_month INTEGER DEFAULT 10,
    max_team_members INTEGER DEFAULT 5,
    max_api_keys INTEGER DEFAULT 3,
    retention_days INTEGER DEFAULT 90, -- How long to keep scan results

    -- Feature flags
    enable_scheduled_scans BOOLEAN DEFAULT false,
    enable_slack_integration BOOLEAN DEFAULT false,
    enable_jira_integration BOOLEAN DEFAULT false,
    enable_custom_branding BOOLEAN DEFAULT false,

    -- Notification preferences
    notify_on_critical BOOLEAN DEFAULT true,
    notify_on_high BOOLEAN DEFAULT true,
    notify_on_new_findings BOOLEAN DEFAULT true,

    -- SLA overrides (null = use severity defaults)
    sla_critical_hours INTEGER,
    sla_high_hours INTEGER,
    sla_medium_hours INTEGER,
    sla_low_hours INTEGER,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- ============================================================================
-- 5. API KEYS (for programmatic access)
-- ============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by UUID NOT NULL REFERENCES users(id),
    name TEXT NOT NULL, -- User-friendly name
    key_hash TEXT NOT NULL UNIQUE, -- SHA256 hash of the actual key
    key_prefix TEXT NOT NULL, -- First 8 chars for display (e.g., "venti_sk_abc123...")
    scopes TEXT[] NOT NULL DEFAULT ARRAY['read:scans'], -- Granular permissions
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),

    CONSTRAINT api_keys_scopes_check CHECK (
        scopes <@ ARRAY[
            'read:scans', 'write:scans', 'read:findings', 'write:findings',
            'read:triage', 'write:triage', 'read:reports', 'admin:all'
        ]
    )
);

CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(organization_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);

-- ============================================================================
-- 6. AUDIT LOG (track all RBAC-related actions)
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL, -- e.g., 'user.invited', 'scan.created', 'finding.triaged'
    resource_type TEXT NOT NULL, -- e.g., 'scan', 'finding', 'user'
    resource_id UUID,
    details JSONB, -- Additional context (IP, user agent, changed fields, etc.)
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_org ON audit_log(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log(resource_type, resource_id);

-- ============================================================================
-- 7. ADD ORGANIZATION_ID TO EXISTING TABLES
-- ============================================================================

-- Add organization_id to scans table
ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id);

CREATE INDEX IF NOT EXISTS idx_scans_organization ON scans(organization_id);

-- Add organization_id to findings table
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_findings_organization ON findings(organization_id);

-- Add organization_id to finding_triage table
ALTER TABLE finding_triage
    ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_triage_organization ON finding_triage(organization_id);

-- Add organization_id to finding_comments table
ALTER TABLE finding_comments
    ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS author_id UUID REFERENCES users(id);

CREATE INDEX IF NOT EXISTS idx_comments_organization ON finding_comments(organization_id);

-- ============================================================================
-- 8. PERMISSION HELPER FUNCTIONS
-- ============================================================================

-- Check if user has role in organization
CREATE OR REPLACE FUNCTION user_has_role(
    p_user_id UUID,
    p_organization_id UUID,
    p_role TEXT
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM organization_memberships
        WHERE user_id = p_user_id
        AND organization_id = p_organization_id
        AND role = p_role
        AND is_active = true
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- Check if user has any of the specified roles
CREATE OR REPLACE FUNCTION user_has_any_role(
    p_user_id UUID,
    p_organization_id UUID,
    p_roles TEXT[]
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM organization_memberships
        WHERE user_id = p_user_id
        AND organization_id = p_organization_id
        AND role = ANY(p_roles)
        AND is_active = true
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- Get user's role in organization
CREATE OR REPLACE FUNCTION get_user_role(
    p_user_id UUID,
    p_organization_id UUID
) RETURNS TEXT AS $$
DECLARE
    v_role TEXT;
BEGIN
    SELECT role INTO v_role
    FROM organization_memberships
    WHERE user_id = p_user_id
    AND organization_id = p_organization_id
    AND is_active = true;

    RETURN v_role;
END;
$$ LANGUAGE plpgsql STABLE;

-- Check if user can access organization
CREATE OR REPLACE FUNCTION user_can_access_org(
    p_user_id UUID,
    p_organization_id UUID
) RETURNS BOOLEAN AS $$
BEGIN
    -- Superusers can access any org
    IF EXISTS (SELECT 1 FROM users WHERE id = p_user_id AND is_superuser = true) THEN
        RETURN true;
    END IF;

    -- Check membership
    RETURN EXISTS (
        SELECT 1 FROM organization_memberships
        WHERE user_id = p_user_id
        AND organization_id = p_organization_id
        AND is_active = true
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- 9. ROW-LEVEL SECURITY (RLS) POLICIES
-- ============================================================================

-- Enable RLS on sensitive tables
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_triage ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_comments ENABLE ROW LEVEL SECURITY;

-- Scans: Users can only see scans from their organization
CREATE POLICY scans_organization_isolation ON scans
    USING (organization_id IN (
        SELECT organization_id FROM organization_memberships
        WHERE user_id = current_setting('app.current_user_id')::UUID
        AND is_active = true
    ));

-- Findings: Users can only see findings from their organization
CREATE POLICY findings_organization_isolation ON findings
    USING (organization_id IN (
        SELECT organization_id FROM organization_memberships
        WHERE user_id = current_setting('app.current_user_id')::UUID
        AND is_active = true
    ));

-- Triage: Users can only see triage data from their organization
CREATE POLICY triage_organization_isolation ON finding_triage
    USING (organization_id IN (
        SELECT organization_id FROM organization_memberships
        WHERE user_id = current_setting('app.current_user_id')::UUID
        AND is_active = true
    ));

-- Comments: Users can only see comments from their organization
CREATE POLICY comments_organization_isolation ON finding_comments
    USING (organization_id IN (
        SELECT organization_id FROM organization_memberships
        WHERE user_id = current_setting('app.current_user_id')::UUID
        AND is_active = true
    ));

-- ============================================================================
-- 10. SEED DATA (Development/Testing)
-- ============================================================================

-- Create default organization
INSERT INTO organizations (id, name, slug, description, tier, is_active)
VALUES (
    '00000000-0000-0000-0000-000000000001'::UUID,
    'Demo Organization',
    'demo-org',
    'Default organization for testing',
    'professional',
    true
) ON CONFLICT (id) DO NOTHING;

-- Create default organization settings
INSERT INTO organization_settings (organization_id, max_scans_per_month, max_team_members)
VALUES (
    '00000000-0000-0000-0000-000000000001'::UUID,
    100,
    10
) ON CONFLICT (organization_id) DO NOTHING;

-- Create default admin user
INSERT INTO users (id, email, username, hashed_password, full_name, is_active, email_verified)
VALUES (
    '00000000-0000-0000-0000-000000000002'::UUID,
    'admin@demo.com',
    'admin',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5aX/vjqB.K/Ci', -- 'admin123'
    'Demo Admin',
    true,
    true
) ON CONFLICT (id) DO NOTHING;

-- Add admin to organization
INSERT INTO organization_memberships (organization_id, user_id, role, joined_at, is_active)
VALUES (
    '00000000-0000-0000-0000-000000000001'::UUID,
    '00000000-0000-0000-0000-000000000002'::UUID,
    'admin',
    NOW(),
    true
) ON CONFLICT (organization_id, user_id) DO NOTHING;

-- ============================================================================
-- 11. VIEWS FOR CONVENIENCE
-- ============================================================================

-- View: Users with their organization roles
CREATE OR REPLACE VIEW user_organization_roles AS
SELECT
    u.id AS user_id,
    u.email,
    u.username,
    u.full_name,
    om.organization_id,
    o.name AS organization_name,
    o.slug AS organization_slug,
    om.role,
    om.is_active AS membership_active,
    u.is_superuser
FROM users u
JOIN organization_memberships om ON u.id = om.user_id
JOIN organizations o ON om.organization_id = o.id
WHERE u.deleted_at IS NULL;

-- View: Organization statistics
CREATE OR REPLACE VIEW organization_stats AS
SELECT
    o.id AS organization_id,
    o.name,
    o.slug,
    o.tier,
    COUNT(DISTINCT om.user_id) AS total_members,
    COUNT(DISTINCT s.id) AS total_scans,
    COUNT(DISTINCT f.id) AS total_findings,
    COUNT(DISTINCT CASE WHEN f.severity = 'Critical' THEN f.id END) AS critical_findings,
    COUNT(DISTINCT ak.id) AS total_api_keys,
    MAX(s.created_at) AS last_scan_at
FROM organizations o
LEFT JOIN organization_memberships om ON o.id = om.organization_id AND om.is_active = true
LEFT JOIN scans s ON o.id = s.organization_id AND s.deleted_at IS NULL
LEFT JOIN findings f ON o.id = f.organization_id AND f.deleted_at IS NULL
LEFT JOIN api_keys ak ON o.id = ak.organization_id AND ak.is_active = true
WHERE o.is_active = true
GROUP BY o.id, o.name, o.slug, o.tier;

-- ============================================================================
-- 12. TRIGGERS
-- ============================================================================

-- Update updated_at timestamp on organizations
CREATE OR REPLACE FUNCTION update_organization_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_organization_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION update_organization_updated_at();

-- Update updated_at timestamp on users
CREATE TRIGGER trigger_update_user_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_organization_updated_at();

-- Update updated_at timestamp on organization_memberships
CREATE TRIGGER trigger_update_membership_updated_at
    BEFORE UPDATE ON organization_memberships
    FOR EACH ROW
    EXECUTE FUNCTION update_organization_updated_at();

COMMENT ON TABLE organizations IS 'Multi-tenant organizations for RBAC isolation';
COMMENT ON TABLE users IS 'User accounts with optional superuser flag';
COMMENT ON TABLE organization_memberships IS 'Junction table: users <-> organizations with roles';
COMMENT ON TABLE organization_settings IS 'Per-organization configuration and feature flags';
COMMENT ON TABLE api_keys IS 'API keys for programmatic access with scoped permissions';
COMMENT ON TABLE audit_log IS 'Audit trail for all RBAC-related actions';
