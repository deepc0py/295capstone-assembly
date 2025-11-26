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

from database_orm import Base, generate_fingerprint


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
# Model: FindingTriage (Week 3)
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


# ============================================================================
# Model: FindingComment (Week 3)
# ============================================================================

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


# ============================================================================
# Model: FindingStatusHistory (Week 3)
# ============================================================================

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
