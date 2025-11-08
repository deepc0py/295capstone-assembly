"""
Triage management for VentiAPI findings.

This module handles:
- Creating and updating triage records
- Status management (new, validated, in_progress, resolved, etc.)
- Assignment workflow
- Comment/note management
- SLA tracking

Week 3: Triage Workflow
"""

import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from uuid import UUID

from sqlalchemy import and_, or_, func, desc
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from models import Finding, FindingTriage, FindingComment, FindingStatusHistory

logger = logging.getLogger(__name__)


# ============================================================================
# Triage Creation and Updates
# ============================================================================

async def create_triage(
    db: Session,
    finding_id: UUID,
    status: str = "new",
    assigned_to: Optional[str] = None,
    assigned_by: Optional[str] = None,
    auto_sla: bool = True,
    sla_days: Optional[int] = None,
    tags: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> FindingTriage:
    """
    Create a triage record for a finding.

    Args:
        db: Database session
        finding_id: UUID of finding to triage
        status: Initial status (default: 'new')
        assigned_to: User to assign finding to
        assigned_by: User who made the assignment
        auto_sla: Automatically calculate SLA based on severity
        sla_days: Custom SLA in days (overrides auto_sla)
        tags: Custom tags for filtering
        metadata: Additional metadata

    Returns:
        FindingTriage: Created triage record

    Raises:
        IntegrityError: If triage already exists for this finding
    """
    try:
        # Get finding to determine SLA
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise ValueError(f"Finding {finding_id} not found")

        # Calculate SLA deadline
        sla_deadline = None
        calculated_sla_days = None

        if sla_days is not None:
            # Use custom SLA
            calculated_sla_days = sla_days
            sla_deadline = datetime.utcnow() + timedelta(days=sla_days)
        elif auto_sla:
            # Use severity-based SLA
            severity_sla_map = {
                "Critical": 2,   # 2 days
                "High": 7,       # 7 days
                "Medium": 30,    # 30 days
                "Low": 90,       # 90 days
            }
            calculated_sla_days = severity_sla_map.get(finding.severity, 30)
            sla_deadline = datetime.utcnow() + timedelta(days=calculated_sla_days)

        # Create triage record
        triage = FindingTriage(
            finding_id=finding_id,
            status=status,
            assigned_to=assigned_to,
            assigned_at=datetime.utcnow() if assigned_to else None,
            assigned_by=assigned_by,
            sla_deadline=sla_deadline,
            sla_days=calculated_sla_days,
            tags=tags or [],
            metadata=metadata or {},
        )

        db.add(triage)
        db.commit()
        db.refresh(triage)

        logger.info(f"Created triage for finding {finding_id} with status {status}")
        return triage

    except IntegrityError as e:
        db.rollback()
        logger.error(f"Triage already exists for finding {finding_id}: {e}")
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create triage: {e}")
        raise


async def update_triage_status(
    db: Session,
    finding_id: UUID,
    new_status: str,
    changed_by: str,
    change_reason: Optional[str] = None,
    validation_notes: Optional[str] = None
) -> FindingTriage:
    """
    Update the status of a finding's triage record.

    Args:
        db: Database session
        finding_id: UUID of finding
        new_status: New status value
        changed_by: User making the change
        change_reason: Optional reason for status change
        validation_notes: Notes if status is 'validated'

    Returns:
        FindingTriage: Updated triage record
    """
    try:
        triage = db.query(FindingTriage).filter(
            FindingTriage.finding_id == finding_id
        ).first()

        if not triage:
            # Create triage if it doesn't exist
            triage = await create_triage(db, finding_id, status=new_status)
            logger.info(f"Auto-created triage for finding {finding_id} with status {new_status}")
            return triage

        # Update status tracking fields
        old_status = triage.status
        triage.status = new_status
        triage.status_changed_by = changed_by
        triage.status_changed_at = datetime.utcnow()

        # Update validation fields if status is 'validated'
        if new_status == 'validated':
            triage.validated_by = changed_by
            triage.validated_at = datetime.utcnow()
            if validation_notes:
                triage.validation_notes = validation_notes

        db.commit()
        db.refresh(triage)

        # Note: status_history is auto-created by database trigger

        logger.info(f"Updated finding {finding_id} status: {old_status} → {new_status}")
        return triage

    except Exception as e:
        db.rollback()
        logger.error(f"Failed to update status for finding {finding_id}: {e}")
        raise


async def assign_finding(
    db: Session,
    finding_id: UUID,
    assigned_to: str,
    assigned_by: str
) -> FindingTriage:
    """
    Assign a finding to a user.

    Args:
        db: Database session
        finding_id: UUID of finding
        assigned_to: User to assign to
        assigned_by: User making the assignment

    Returns:
        FindingTriage: Updated triage record
    """
    try:
        triage = db.query(FindingTriage).filter(
            FindingTriage.finding_id == finding_id
        ).first()

        if not triage:
            # Create triage if it doesn't exist
            triage = await create_triage(
                db,
                finding_id,
                assigned_to=assigned_to,
                assigned_by=assigned_by
            )
            logger.info(f"Auto-created triage and assigned finding {finding_id} to {assigned_to}")
            return triage

        # Update assignment fields
        triage.assigned_to = assigned_to
        triage.assigned_at = datetime.utcnow()
        triage.assigned_by = assigned_by

        db.commit()
        db.refresh(triage)

        logger.info(f"Assigned finding {finding_id} to {assigned_to}")
        return triage

    except Exception as e:
        db.rollback()
        logger.error(f"Failed to assign finding {finding_id}: {e}")
        raise


async def mark_risk_accepted(
    db: Session,
    finding_id: UUID,
    accepted_by: str,
    reason: str
) -> FindingTriage:
    """
    Mark a finding as risk accepted.

    Args:
        db: Database session
        finding_id: UUID of finding
        accepted_by: User accepting the risk
        reason: Reason for risk acceptance

    Returns:
        FindingTriage: Updated triage record
    """
    try:
        triage = await update_triage_status(
            db,
            finding_id,
            new_status='risk_accepted',
            changed_by=accepted_by,
            change_reason=reason
        )

        triage.risk_accepted_by = accepted_by
        triage.risk_accepted_at = datetime.utcnow()
        triage.risk_acceptance_reason = reason

        db.commit()
        db.refresh(triage)

        logger.info(f"Marked finding {finding_id} as risk accepted by {accepted_by}")
        return triage

    except Exception as e:
        db.rollback()
        logger.error(f"Failed to mark finding {finding_id} as risk accepted: {e}")
        raise


# ============================================================================
# Comment Management
# ============================================================================

async def add_comment(
    db: Session,
    finding_id: UUID,
    author: str,
    comment: str,
    comment_type: str = "note",
    is_internal: bool = False,
    mentions: Optional[List[str]] = None
) -> FindingComment:
    """
    Add a comment to a finding.

    Args:
        db: Database session
        finding_id: UUID of finding
        author: User adding the comment
        comment: Comment text
        comment_type: Type of comment (note, analysis, remediation, escalation, resolution)
        is_internal: Whether comment is internal-only
        mentions: List of @mentioned users

    Returns:
        FindingComment: Created comment record
    """
    try:
        comment_record = FindingComment(
            finding_id=finding_id,
            author=author,
            comment=comment,
            comment_type=comment_type,
            is_internal=is_internal,
            mentions=mentions or [],
        )

        db.add(comment_record)
        db.commit()
        db.refresh(comment_record)

        logger.info(f"Added comment to finding {finding_id} by {author}")
        return comment_record

    except Exception as e:
        db.rollback()
        logger.error(f"Failed to add comment to finding {finding_id}: {e}")
        raise


async def get_comments(
    db: Session,
    finding_id: UUID,
    include_internal: bool = True
) -> List[FindingComment]:
    """
    Get all comments for a finding.

    Args:
        db: Database session
        finding_id: UUID of finding
        include_internal: Whether to include internal comments

    Returns:
        List[FindingComment]: List of comments
    """
    try:
        query = db.query(FindingComment).filter(
            FindingComment.finding_id == finding_id
        )

        if not include_internal:
            query = query.filter(FindingComment.is_internal == False)

        comments = query.order_by(FindingComment.created_at.asc()).all()

        return comments

    except Exception as e:
        logger.error(f"Failed to get comments for finding {finding_id}: {e}")
        raise


# ============================================================================
# Triage Queries
# ============================================================================

async def get_triage(
    db: Session,
    finding_id: UUID
) -> Optional[FindingTriage]:
    """
    Get triage record for a finding.

    Args:
        db: Database session
        finding_id: UUID of finding

    Returns:
        FindingTriage: Triage record, or None if not found
    """
    try:
        triage = db.query(FindingTriage).filter(
            FindingTriage.finding_id == finding_id
        ).first()

        return triage

    except Exception as e:
        logger.error(f"Failed to get triage for finding {finding_id}: {e}")
        raise


async def list_triaged_findings(
    db: Session,
    scan_id: Optional[UUID] = None,
    status: Optional[str] = None,
    assigned_to: Optional[str] = None,
    overdue_only: bool = False,
    limit: int = 50,
    offset: int = 0
) -> Tuple[List[Dict[str, Any]], int]:
    """
    List triaged findings with filtering.

    Args:
        db: Database session
        scan_id: Filter by scan ID
        status: Filter by triage status
        assigned_to: Filter by assignee
        overdue_only: Show only overdue findings
        limit: Maximum results
        offset: Pagination offset

    Returns:
        Tuple[List[Dict], int]: List of findings with triage info and total count
    """
    try:
        # Build query
        query = db.query(Finding).join(
            FindingTriage,
            Finding.id == FindingTriage.finding_id
        )

        # Apply filters
        if scan_id:
            query = query.filter(Finding.scan_id == scan_id)

        if status:
            query = query.filter(FindingTriage.status == status)

        if assigned_to:
            query = query.filter(FindingTriage.assigned_to == assigned_to)

        if overdue_only:
            query = query.filter(
                and_(
                    FindingTriage.sla_deadline < datetime.utcnow(),
                    FindingTriage.status.notin_(['resolved', 'risk_accepted', 'false_positive'])
                )
            )

        # Get total count
        total_count = query.count()

        # Apply ordering and pagination
        findings = query.order_by(
            FindingTriage.sla_deadline.asc().nullslast()
        ).limit(limit).offset(offset).all()

        # Convert to dict with triage info
        result = []
        for finding in findings:
            finding_dict = finding.to_dict()
            finding_dict['triage'] = finding.triage.to_dict() if finding.triage else None
            finding_dict['comment_count'] = len(finding.comments) if finding.comments else 0
            result.append(finding_dict)

        return result, total_count

    except Exception as e:
        logger.error(f"Failed to list triaged findings: {e}")
        raise


async def get_overdue_findings(
    db: Session,
    assigned_to: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Get all overdue findings.

    Args:
        db: Database session
        assigned_to: Filter by assignee (optional)

    Returns:
        List[Dict]: List of overdue findings with triage info
    """
    try:
        query = db.query(Finding).join(
            FindingTriage,
            Finding.id == FindingTriage.finding_id
        ).filter(
            and_(
                FindingTriage.sla_deadline < datetime.utcnow(),
                FindingTriage.status.notin_(['resolved', 'risk_accepted', 'false_positive', 'wont_fix'])
            )
        )

        if assigned_to:
            query = query.filter(FindingTriage.assigned_to == assigned_to)

        findings = query.order_by(FindingTriage.sla_deadline.asc()).all()

        # Convert to dict with days overdue
        result = []
        for finding in findings:
            finding_dict = finding.to_dict()
            triage_dict = finding.triage.to_dict()

            # Calculate days overdue
            days_overdue = (datetime.utcnow() - finding.triage.sla_deadline).days
            triage_dict['days_overdue'] = days_overdue

            finding_dict['triage'] = triage_dict
            result.append(finding_dict)

        return result

    except Exception as e:
        logger.error(f"Failed to get overdue findings: {e}")
        raise


async def get_triage_metrics(
    db: Session,
    scan_id: Optional[UUID] = None,
    assigned_to: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get triage metrics and statistics.

    Args:
        db: Database session
        scan_id: Filter by scan ID (optional)
        assigned_to: Filter by assignee (optional)

    Returns:
        Dict: Triage metrics
    """
    try:
        # Build base query
        query = db.query(FindingTriage)

        if scan_id:
            query = query.join(Finding).filter(Finding.scan_id == scan_id)

        if assigned_to:
            query = query.filter(FindingTriage.assigned_to == assigned_to)

        # Get all triage records
        triages = query.all()

        # Calculate metrics
        total = len(triages)
        status_counts = {}
        overdue_count = 0
        assigned_count = 0

        for triage in triages:
            # Count by status
            status_counts[triage.status] = status_counts.get(triage.status, 0) + 1

            # Count overdue
            if (triage.sla_deadline and
                triage.sla_deadline < datetime.utcnow() and
                triage.status not in ['resolved', 'risk_accepted', 'false_positive']):
                overdue_count += 1

            # Count assigned
            if triage.assigned_to:
                assigned_count += 1

        # Calculate average time to validate (hours)
        validated = [t for t in triages if t.validated_at]
        avg_hours_to_validate = None
        if validated:
            hours = [(t.validated_at - t.created_at).total_seconds() / 3600 for t in validated]
            avg_hours_to_validate = sum(hours) / len(hours)

        # Calculate average time to resolve (hours)
        resolved = [t for t in triages if t.status == 'resolved']
        avg_hours_to_resolve = None
        if resolved:
            hours = [(t.status_changed_at - t.created_at).total_seconds() / 3600 for t in resolved]
            avg_hours_to_resolve = sum(hours) / len(hours)

        return {
            "total_triaged": total,
            "status_counts": status_counts,
            "overdue_count": overdue_count,
            "assigned_count": assigned_count,
            "avg_hours_to_validate": round(avg_hours_to_validate, 2) if avg_hours_to_validate else None,
            "avg_hours_to_resolve": round(avg_hours_to_resolve, 2) if avg_hours_to_resolve else None,
        }

    except Exception as e:
        logger.error(f"Failed to get triage metrics: {e}")
        raise


async def get_status_history(
    db: Session,
    finding_id: UUID
) -> List[FindingStatusHistory]:
    """
    Get status change history for a finding.

    Args:
        db: Database session
        finding_id: UUID of finding

    Returns:
        List[FindingStatusHistory]: List of status changes
    """
    try:
        history = db.query(FindingStatusHistory).filter(
            FindingStatusHistory.finding_id == finding_id
        ).order_by(FindingStatusHistory.created_at.asc()).all()

        return history

    except Exception as e:
        logger.error(f"Failed to get status history for finding {finding_id}: {e}")
        raise


# ============================================================================
# Bulk Operations
# ============================================================================

async def bulk_assign(
    db: Session,
    finding_ids: List[UUID],
    assigned_to: str,
    assigned_by: str
) -> List[FindingTriage]:
    """
    Assign multiple findings to a user.

    Args:
        db: Database session
        finding_ids: List of finding UUIDs
        assigned_to: User to assign to
        assigned_by: User making the assignment

    Returns:
        List[FindingTriage]: Updated triage records
    """
    try:
        triages = []
        for finding_id in finding_ids:
            triage = await assign_finding(db, finding_id, assigned_to, assigned_by)
            triages.append(triage)

        logger.info(f"Bulk assigned {len(finding_ids)} findings to {assigned_to}")
        return triages

    except Exception as e:
        db.rollback()
        logger.error(f"Failed to bulk assign findings: {e}")
        raise


async def bulk_update_status(
    db: Session,
    finding_ids: List[UUID],
    new_status: str,
    changed_by: str,
    change_reason: Optional[str] = None
) -> List[FindingTriage]:
    """
    Update status for multiple findings.

    Args:
        db: Database session
        finding_ids: List of finding UUIDs
        new_status: New status value
        changed_by: User making the change
        change_reason: Optional reason for status change

    Returns:
        List[FindingTriage]: Updated triage records
    """
    try:
        triages = []
        for finding_id in finding_ids:
            triage = await update_triage_status(
                db,
                finding_id,
                new_status,
                changed_by,
                change_reason
            )
            triages.append(triage)

        logger.info(f"Bulk updated {len(finding_ids)} findings to status {new_status}")
        return triages

    except Exception as e:
        db.rollback()
        logger.error(f"Failed to bulk update status: {e}")
        raise
