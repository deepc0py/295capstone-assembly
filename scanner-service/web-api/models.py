"""
SQLAlchemy models for VentiAPI scan history.

These models map to the PostgreSQL schema defined in
database/init/002_scan_history_schema.sql

Week 2: Scan History & Trending
"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    Column, String, Integer, Boolean, TIMESTAMP, ForeignKey, ARRAY,
    CheckConstraint, Text, DECIMAL, Index
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database import Base, generate_fingerprint


# ============================================================================
# Model: Scan
# ============================================================================

class Scan(Base):
    """
    Represents a security scan of an API.

    Stores metadata about scan configuration, status, and summary statistics.
    """
    __tablename__ = "scans"

    # Primary key
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(String, unique=True, nullable=False, index=True)

    # Scan target
    api_base_url = Column(String, nullable=False, index=True)

    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())
    completed_at = Column(TIMESTAMP(timezone=True), nullable=True)

    # User tracking
    created_by = Column(String, nullable=True, index=True)

    # Scan status
    status = Column(
        String,
        nullable=False,
        default='pending',
        index=True
    )

    # Summary counts (denormalized for performance)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    # Scanner configuration
    scanner_engines = Column(ARRAY(String), nullable=True)
    dangerous_mode = Column(Boolean, default=False)
    fuzz_auth = Column(Boolean, default=False)
    max_requests = Column(Integer, nullable=True)

    # Additional metadata
    openapi_spec_path = Column(String, nullable=True)
    openapi_spec_url = Column(String, nullable=True)
    metadata = Column(JSONB, default={})

    # Soft delete
    deleted_at = Column(TIMESTAMP(timezone=True), nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    comparisons_as_current = relationship(
        "ScanComparison",
        foreign_keys="ScanComparison.scan_id",
        back_populates="scan"
    )
    comparisons_as_previous = relationship(
        "ScanComparison",
        foreign_keys="ScanComparison.previous_scan_id",
        back_populates="previous_scan"
    )

    # Table constraints
    __table_args__ = (
        CheckConstraint('total_findings >= 0', name='valid_total_findings'),
        CheckConstraint('critical_count >= 0', name='valid_critical_count'),
        CheckConstraint('high_count >= 0', name='valid_high_count'),
        CheckConstraint('medium_count >= 0', name='valid_medium_count'),
        CheckConstraint('low_count >= 0', name='valid_low_count'),
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed')",
            name='valid_status'
        ),
        Index('idx_scans_api_created', 'api_base_url', 'created_at'),
        Index('idx_scans_user_created', 'created_by', 'created_at'),
    )

    def __repr__(self):
        return f"<Scan(id={self.id}, scan_id={self.scan_id}, status={self.status})>"

    def to_dict(self) -> dict:
        """Convert scan to dictionary for API responses."""
        return {
            "id": str(self.id),
            "scan_id": self.scan_id,
            "api_base_url": self.api_base_url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_by": self.created_by,
            "status": self.status,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "scanner_engines": self.scanner_engines,
            "dangerous_mode": self.dangerous_mode,
            "fuzz_auth": self.fuzz_auth,
            "max_requests": self.max_requests,
            "openapi_spec_path": self.openapi_spec_path,
            "openapi_spec_url": self.openapi_spec_url,
            "metadata": self.metadata,
        }


# ============================================================================
# Model: Finding
# ============================================================================

class Finding(Base):
    """
    Represents a security vulnerability finding from a scan.

    Stores detailed information about each discovered vulnerability.
    """
    __tablename__ = "findings"

    # Primary key
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(PG_UUID(as_uuid=True), ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

    # Vulnerability identification
    rule = Column(String, nullable=False, index=True)  # 'API1', 'API2', etc.
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, index=True)
    score = Column(DECIMAL(4, 2), nullable=True)  # 0.00 - 10.00

    # Affected resource
    endpoint = Column(String, nullable=False, index=True)
    method = Column(String, nullable=False)

    # Vulnerability details
    description = Column(Text, nullable=True)
    evidence = Column(JSONB, default={})

    # Scanner attribution
    scanner = Column(String, nullable=False)
    scanner_description = Column(Text, nullable=True)

    # CWE/CVE mappings
    cwe_ids = Column(ARRAY(String), nullable=True)
    cve_ids = Column(ARRAY(String), nullable=True)

    # Fingerprint for deduplication
    fingerprint = Column(String, nullable=False, index=True)

    # Additional metadata
    metadata = Column(JSONB, default={})

    # Relationships
    scan = relationship("Scan", back_populates="findings")
    triage = relationship("FindingTriage", back_populates="finding", uselist=False, cascade="all, delete-orphan")
    comments = relationship("FindingComment", back_populates="finding", cascade="all, delete-orphan")
    status_history = relationship("FindingStatusHistory", back_populates="finding", cascade="all, delete-orphan")

    # Table constraints
    __table_args__ = (
        CheckConstraint(
            "severity IN ('Critical', 'High', 'Medium', 'Low', 'Info')",
            name='valid_severity'
        ),
        CheckConstraint(
            "score IS NULL OR (score >= 0 AND score <= 10)",
            name='valid_score'
        ),
        Index('idx_findings_scan_fingerprint', 'scan_id', 'fingerprint'),
    )

    def __repr__(self):
        return f"<Finding(id={self.id}, rule={self.rule}, endpoint={self.endpoint})>"

    def to_dict(self) -> dict:
        """Convert finding to dictionary for API responses."""
        return {
            "id": str(self.id),
            "scan_id": str(self.scan_id),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity,
            "score": float(self.score) if self.score else None,
            "endpoint": self.endpoint,
            "method": self.method,
            "description": self.description,
            "evidence": self.evidence,
            "scanner": self.scanner,
            "scanner_description": self.scanner_description,
            "cwe_ids": self.cwe_ids,
            "cve_ids": self.cve_ids,
            "fingerprint": self.fingerprint,
            "metadata": self.metadata,
        }

    @staticmethod
    def calculate_fingerprint(rule: str, endpoint: str, method: str) -> str:
        """
        Calculate fingerprint for this finding.

        Args:
            rule: OWASP API rule
            endpoint: API endpoint
            method: HTTP method

        Returns:
            str: Fingerprint hash
        """
        return generate_fingerprint(rule, endpoint, method)


# ============================================================================
# Model: ScanComparison
# ============================================================================

class ScanComparison(Base):
    """
    Represents a comparison between two scans.

    Caches comparison results for performance (new/resolved/regressed findings).
    """
    __tablename__ = "scan_comparisons"

    # Primary key
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(PG_UUID(as_uuid=True), ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    previous_scan_id = Column(PG_UUID(as_uuid=True), ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

    # Comparison results
    new_findings = Column(Integer, default=0)
    resolved_findings = Column(Integer, default=0)
    regressed_findings = Column(Integer, default=0)
    unchanged_findings = Column(Integer, default=0)

    # Finding IDs
    new_finding_ids = Column(ARRAY(PG_UUID(as_uuid=True)), default=[])
    resolved_finding_ids = Column(ARRAY(PG_UUID(as_uuid=True)), default=[])
    regressed_finding_ids = Column(ARRAY(PG_UUID(as_uuid=True)), default=[])

    # Cache
    comparison_data = Column(JSONB, default={})

    # Relationships
    scan = relationship("Scan", foreign_keys=[scan_id], back_populates="comparisons_as_current")
    previous_scan = relationship("Scan", foreign_keys=[previous_scan_id], back_populates="comparisons_as_previous")

    # Table constraints
    __table_args__ = (
        CheckConstraint('scan_id != previous_scan_id', name='different_scans'),
        CheckConstraint('new_findings >= 0', name='valid_new_findings'),
        CheckConstraint('resolved_findings >= 0', name='valid_resolved_findings'),
        CheckConstraint('regressed_findings >= 0', name='valid_regressed_findings'),
        CheckConstraint('unchanged_findings >= 0', name='valid_unchanged_findings'),
        Index('idx_comparisons_unique_pair', 'scan_id', 'previous_scan_id', unique=True),
    )

    def __repr__(self):
        return f"<ScanComparison(scan_id={self.scan_id}, previous_scan_id={self.previous_scan_id})>"

    def to_dict(self) -> dict:
        """Convert comparison to dictionary for API responses."""
        return {
            "id": str(self.id),
            "scan_id": str(self.scan_id),
            "previous_scan_id": str(self.previous_scan_id),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "new_findings": self.new_findings,
            "resolved_findings": self.resolved_findings,
            "regressed_findings": self.regressed_findings,
            "unchanged_findings": self.unchanged_findings,
            "new_finding_ids": [str(fid) for fid in self.new_finding_ids] if self.new_finding_ids else [],
            "resolved_finding_ids": [str(fid) for fid in self.resolved_finding_ids] if self.resolved_finding_ids else [],
            "regressed_finding_ids": [str(fid) for fid in self.regressed_finding_ids] if self.regressed_finding_ids else [],
            "comparison_data": self.comparison_data,
        }


# ============================================================================
# Triage Models (Week 3)
# ============================================================================

class FindingTriage(Base):
    """
    Finding triage information for analyst workflow.

    Tracks status, assignment, validation, and SLA for individual findings.
    Week 3: Triage Workflow
    """
    __tablename__ = "finding_triage"

    # Primary key
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    finding_id = Column(PG_UUID(as_uuid=True), ForeignKey('findings.id', ondelete='CASCADE'), nullable=False, unique=True)

    # Status tracking
    status = Column(String, nullable=False, default='new')
    previous_status = Column(String, nullable=True)
    status_changed_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    status_changed_by = Column(String, nullable=True)

    # Assignment tracking
    assigned_to = Column(String, nullable=True)
    assigned_at = Column(TIMESTAMP(timezone=True), nullable=True)
    assigned_by = Column(String, nullable=True)

    # Validation tracking
    validated_by = Column(String, nullable=True)
    validated_at = Column(TIMESTAMP(timezone=True), nullable=True)
    validation_notes = Column(Text, nullable=True)

    # SLA tracking
    sla_deadline = Column(TIMESTAMP(timezone=True), nullable=True)
    sla_days = Column(Integer, nullable=True)
    # is_overdue is a computed column in PostgreSQL, not defined in SQLAlchemy

    # Risk acceptance
    risk_acceptance_reason = Column(Text, nullable=True)
    risk_accepted_by = Column(String, nullable=True)
    risk_accepted_at = Column(TIMESTAMP(timezone=True), nullable=True)

    # Metadata
    priority_override = Column(Integer, nullable=True)
    tags = Column(ARRAY(String), default=[])
    metadata = Column(JSONB, default={})

    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    finding = relationship("Finding", back_populates="triage", uselist=False)
    comments = relationship("FindingComment", back_populates="triage", cascade="all, delete-orphan")
    status_history = relationship("FindingStatusHistory", back_populates="triage", cascade="all, delete-orphan")

    # Table constraints
    __table_args__ = (
        CheckConstraint(
            "status IN ('new', 'validated', 'false_positive', 'duplicate', 'risk_accepted', 'in_progress', 'resolved', 'wont_fix')",
            name='finding_triage_status_check'
        ),
        CheckConstraint(
            'priority_override IS NULL OR (priority_override >= 0 AND priority_override <= 100)',
            name='valid_priority_override'
        ),
    )

    def __repr__(self):
        return f"<FindingTriage(finding_id={self.finding_id}, status={self.status})>"

    def to_dict(self) -> dict:
        """Convert triage info to dictionary for API responses."""
        return {
            "id": str(self.id),
            "finding_id": str(self.finding_id),
            "status": self.status,
            "previous_status": self.previous_status,
            "status_changed_at": self.status_changed_at.isoformat() if self.status_changed_at else None,
            "status_changed_by": self.status_changed_by,
            "assigned_to": self.assigned_to,
            "assigned_at": self.assigned_at.isoformat() if self.assigned_at else None,
            "assigned_by": self.assigned_by,
            "validated_by": self.validated_by,
            "validated_at": self.validated_at.isoformat() if self.validated_at else None,
            "validation_notes": self.validation_notes,
            "sla_deadline": self.sla_deadline.isoformat() if self.sla_deadline else None,
            "sla_days": self.sla_days,
            "risk_acceptance_reason": self.risk_acceptance_reason,
            "risk_accepted_by": self.risk_accepted_by,
            "risk_accepted_at": self.risk_accepted_at.isoformat() if self.risk_accepted_at else None,
            "priority_override": self.priority_override,
            "tags": self.tags if self.tags else [],
            "metadata": self.metadata if self.metadata else {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class FindingComment(Base):
    """
    Comments and notes on findings for analyst collaboration.

    Supports @mentions, attachments, and different comment types.
    Week 3: Triage Workflow
    """
    __tablename__ = "finding_comments"

    # Primary key
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    finding_id = Column(PG_UUID(as_uuid=True), ForeignKey('findings.id', ondelete='CASCADE'), nullable=False)

    # Comment content
    author = Column(String, nullable=False)
    comment = Column(Text, nullable=False)
    comment_type = Column(String, default='note')

    # Metadata
    is_internal = Column(Boolean, default=False)
    mentions = Column(ARRAY(String), default=[])
    attachments = Column(JSONB, default=[])

    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())
    edited_by = Column(String, nullable=True)

    # Relationships
    finding = relationship("Finding", back_populates="comments")
    triage = relationship("FindingTriage", back_populates="comments")

    # Table constraints
    __table_args__ = (
        CheckConstraint(
            "comment_type IN ('note', 'analysis', 'remediation', 'escalation', 'resolution')",
            name='finding_comments_comment_type_check'
        ),
    )

    def __repr__(self):
        return f"<FindingComment(finding_id={self.finding_id}, author={self.author})>"

    def to_dict(self) -> dict:
        """Convert comment to dictionary for API responses."""
        return {
            "id": str(self.id),
            "finding_id": str(self.finding_id),
            "author": self.author,
            "comment": self.comment,
            "comment_type": self.comment_type,
            "is_internal": self.is_internal,
            "mentions": self.mentions if self.mentions else [],
            "attachments": self.attachments if self.attachments else [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "edited_by": self.edited_by,
        }


class FindingStatusHistory(Base):
    """
    Audit trail for finding status changes.

    Records every status transition with context and timestamp.
    Week 3: Triage Workflow
    """
    __tablename__ = "finding_status_history"

    # Primary key
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    finding_id = Column(PG_UUID(as_uuid=True), ForeignKey('findings.id', ondelete='CASCADE'), nullable=False)

    # Status change tracking
    old_status = Column(String, nullable=True)
    new_status = Column(String, nullable=False)
    changed_by = Column(String, nullable=False)
    change_reason = Column(Text, nullable=True)

    # Context at time of change
    assigned_to = Column(String, nullable=True)
    sla_deadline = Column(TIMESTAMP(timezone=True), nullable=True)

    # Timestamp
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

    # Relationships
    finding = relationship("Finding", back_populates="status_history")
    triage = relationship("FindingTriage", back_populates="status_history")

    def __repr__(self):
        return f"<FindingStatusHistory(finding_id={self.finding_id}, {self.old_status} → {self.new_status})>"

    def to_dict(self) -> dict:
        """Convert status history to dictionary for API responses."""
        return {
            "id": str(self.id),
            "finding_id": str(self.finding_id),
            "old_status": self.old_status,
            "new_status": self.new_status,
            "changed_by": self.changed_by,
            "change_reason": self.change_reason,
            "assigned_to": self.assigned_to,
            "sla_deadline": self.sla_deadline.isoformat() if self.sla_deadline else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# ============================================================================
# Week 4: RBAC & Organization Models
# ============================================================================

class Organization(Base):
    """
    Multi-tenant organization for RBAC isolation.

    Each organization has its own scans, findings, and team members.
    Week 4: RBAC & Organization Isolation
    """
    __tablename__ = "organizations"

    # Primary key
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String, nullable=False)
    slug = Column(String, unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)

    # Tier and status
    tier = Column(String, nullable=False, default='free')
    is_active = Column(Boolean, nullable=False, default=True, index=True)

    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    memberships = relationship("OrganizationMembership", back_populates="organization", cascade="all, delete-orphan")
    settings = relationship("OrganizationSettings", back_populates="organization", uselist=False, cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="organization", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="organization", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="organization", cascade="all, delete-orphan")

    # Constraints
    __table_args__ = (
        CheckConstraint("tier IN ('free', 'starter', 'professional', 'enterprise')", name='valid_tier'),
        Index('idx_organizations_slug', 'slug'),
        Index('idx_organizations_is_active', 'is_active'),
    )

    def __repr__(self):
        return f"<Organization(slug={self.slug}, tier={self.tier})>"

    def to_dict(self) -> dict:
        """Convert organization to dictionary for API responses."""
        return {
            "id": str(self.id),
            "name": self.name,
            "slug": self.slug,
            "description": self.description,
            "tier": self.tier,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class User(Base):
    """
    User account with authentication credentials.

    Can belong to multiple organizations with different roles.
    Week 4: RBAC & Organization Isolation
    """
    __tablename__ = "users"

    # Primary key
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    email = Column(String, unique=True, nullable=False, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)

    # Flags
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    is_superuser = Column(Boolean, nullable=False, default=False)
    email_verified = Column(Boolean, nullable=False, default=False)

    # Timestamps
    last_login = Column(TIMESTAMP(timezone=True), nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())
    deleted_at = Column(TIMESTAMP(timezone=True), nullable=True)  # Soft delete

    # Relationships
    memberships = relationship("OrganizationMembership", back_populates="user", cascade="all, delete-orphan")
    created_api_keys = relationship("ApiKey", back_populates="created_by_user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index('idx_users_email', 'email'),
        Index('idx_users_username', 'username'),
        Index('idx_users_is_active', 'is_active'),
    )

    def __repr__(self):
        return f"<User(username={self.username}, email={self.email})>"

    def to_dict(self, include_sensitive: bool = False) -> dict:
        """Convert user to dictionary for API responses."""
        data = {
            "id": str(self.id),
            "email": self.email,
            "username": self.username,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "is_superuser": self.is_superuser,
            "email_verified": self.email_verified,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_sensitive:
            data["deleted_at"] = self.deleted_at.isoformat() if self.deleted_at else None
        return data


class OrganizationMembership(Base):
    """
    Junction table: Users <-> Organizations with roles.

    Defines user's role within a specific organization.
    Week 4: RBAC & Organization Isolation
    """
    __tablename__ = "organization_memberships"

    # Primary key
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(PG_UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)

    # Role and status
    role = Column(String, nullable=False, default='viewer', index=True)
    is_active = Column(Boolean, nullable=False, default=True)

    # Invitation tracking
    invited_by = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    invited_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    joined_at = Column(TIMESTAMP(timezone=True), nullable=True)

    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    organization = relationship("Organization", back_populates="memberships")
    user = relationship("User", back_populates="memberships", foreign_keys=[user_id])
    inviter = relationship("User", foreign_keys=[invited_by])

    # Constraints
    __table_args__ = (
        CheckConstraint("role IN ('admin', 'analyst', 'viewer')", name='valid_role'),
        Index('idx_memberships_org', 'organization_id'),
        Index('idx_memberships_user', 'user_id'),
        Index('idx_memberships_role', 'role'),
        {'extend_existing': True}  # Allow unique constraint to be defined separately
    )

    def __repr__(self):
        return f"<OrganizationMembership(org={self.organization_id}, user={self.user_id}, role={self.role})>"

    def to_dict(self) -> dict:
        """Convert membership to dictionary for API responses."""
        return {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "user_id": str(self.user_id),
            "role": self.role,
            "is_active": self.is_active,
            "invited_by": str(self.invited_by) if self.invited_by else None,
            "invited_at": self.invited_at.isoformat() if self.invited_at else None,
            "joined_at": self.joined_at.isoformat() if self.joined_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class OrganizationSettings(Base):
    """
    Per-organization configuration and feature flags.

    Controls limits, features, and notification preferences.
    Week 4: RBAC & Organization Isolation
    """
    __tablename__ = "organization_settings"

    # Primary key (one-to-one with organizations)
    organization_id = Column(PG_UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='CASCADE'), primary_key=True)

    # Limits
    max_scans_per_month = Column(Integer, default=10)
    max_team_members = Column(Integer, default=5)
    max_api_keys = Column(Integer, default=3)
    retention_days = Column(Integer, default=90)

    # Feature flags
    enable_scheduled_scans = Column(Boolean, default=False)
    enable_slack_integration = Column(Boolean, default=False)
    enable_jira_integration = Column(Boolean, default=False)
    enable_custom_branding = Column(Boolean, default=False)

    # Notification preferences
    notify_on_critical = Column(Boolean, default=True)
    notify_on_high = Column(Boolean, default=True)
    notify_on_new_findings = Column(Boolean, default=True)

    # SLA overrides (null = use severity defaults)
    sla_critical_hours = Column(Integer, nullable=True)
    sla_high_hours = Column(Integer, nullable=True)
    sla_medium_hours = Column(Integer, nullable=True)
    sla_low_hours = Column(Integer, nullable=True)

    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    organization = relationship("Organization", back_populates="settings")

    def __repr__(self):
        return f"<OrganizationSettings(org={self.organization_id}, tier={self.organization.tier if self.organization else 'unknown'})>"

    def to_dict(self) -> dict:
        """Convert settings to dictionary for API responses."""
        return {
            "organization_id": str(self.organization_id),
            "max_scans_per_month": self.max_scans_per_month,
            "max_team_members": self.max_team_members,
            "max_api_keys": self.max_api_keys,
            "retention_days": self.retention_days,
            "enable_scheduled_scans": self.enable_scheduled_scans,
            "enable_slack_integration": self.enable_slack_integration,
            "enable_jira_integration": self.enable_jira_integration,
            "enable_custom_branding": self.enable_custom_branding,
            "notify_on_critical": self.notify_on_critical,
            "notify_on_high": self.notify_on_high,
            "notify_on_new_findings": self.notify_on_new_findings,
            "sla_critical_hours": self.sla_critical_hours,
            "sla_high_hours": self.sla_high_hours,
            "sla_medium_hours": self.sla_medium_hours,
            "sla_low_hours": self.sla_low_hours,
        }


class ApiKey(Base):
    """
    API keys for programmatic access with scoped permissions.

    Each key belongs to an organization and has granular scopes.
    Week 4: RBAC & Organization Isolation
    """
    __tablename__ = "api_keys"

    # Primary key
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(PG_UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)
    created_by = Column(PG_UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)

    # Key details
    name = Column(String, nullable=False)
    key_hash = Column(String, unique=True, nullable=False, index=True)
    key_prefix = Column(String, nullable=False, index=True)
    scopes = Column(ARRAY(String), nullable=False, default=['read:scans'])

    # Status and expiration
    is_active = Column(Boolean, nullable=False, default=True)
    last_used_at = Column(TIMESTAMP(timezone=True), nullable=True)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=True)

    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

    # Relationships
    organization = relationship("Organization", back_populates="api_keys")
    created_by_user = relationship("User", back_populates="created_api_keys")

    # Indexes
    __table_args__ = (
        Index('idx_api_keys_org', 'organization_id'),
        Index('idx_api_keys_hash', 'key_hash'),
        Index('idx_api_keys_prefix', 'key_prefix'),
    )

    def __repr__(self):
        return f"<ApiKey(name={self.name}, prefix={self.key_prefix})>"

    def to_dict(self, include_hash: bool = False) -> dict:
        """Convert API key to dictionary for API responses."""
        data = {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "created_by": str(self.created_by),
            "name": self.name,
            "key_prefix": self.key_prefix,
            "scopes": self.scopes if self.scopes else [],
            "is_active": self.is_active,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_hash:
            data["key_hash"] = self.key_hash
        return data


class AuditLog(Base):
    """
    Audit trail for all RBAC-related actions.

    Tracks user actions, IP addresses, and resource changes.
    Week 4: RBAC & Organization Isolation
    """
    __tablename__ = "audit_log"

    # Primary key
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(PG_UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='SET NULL'), nullable=True, index=True)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)

    # Action details
    action = Column(String, nullable=False, index=True)
    resource_type = Column(String, nullable=False)
    resource_id = Column(PG_UUID(as_uuid=True), nullable=True)
    details = Column(JSONB, default={})

    # Request context
    ip_address = Column(String, nullable=True)  # Using String instead of INET for simplicity
    user_agent = Column(Text, nullable=True)

    # Timestamp
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

    # Relationships
    organization = relationship("Organization", back_populates="audit_logs")
    user = relationship("User", back_populates="audit_logs")

    # Indexes
    __table_args__ = (
        Index('idx_audit_log_org', 'organization_id', 'created_at'),
        Index('idx_audit_log_user', 'user_id', 'created_at'),
        Index('idx_audit_log_action', 'action'),
        Index('idx_audit_log_resource', 'resource_type', 'resource_id'),
    )

    def __repr__(self):
        return f"<AuditLog(action={self.action}, resource_type={self.resource_type})>"

    def to_dict(self) -> dict:
        """Convert audit log entry to dictionary for API responses."""
        return {
            "id": str(self.id),
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "user_id": str(self.user_id) if self.user_id else None,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": str(self.resource_id) if self.resource_id else None,
            "details": self.details if self.details else {},
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# Update existing Scan model to include organization relationship
Scan.organization_id = Column(PG_UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True, index=True)
Scan.organization = relationship("Organization", back_populates="scans")
