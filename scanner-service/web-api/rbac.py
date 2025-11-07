"""
RBAC (Role-Based Access Control) authentication and authorization.

Week 4: Multi-tenant organization isolation with permission checks.
"""

import hashlib
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from uuid import UUID
from functools import wraps

from fastapi import HTTPException, Depends, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from models import User, Organization, OrganizationMembership, ApiKey, AuditLog
from database import get_db


# ============================================================================
# Configuration
# ============================================================================

SECRET_KEY = os.getenv("JWT_SECRET", "insecure-dev-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security_scheme = HTTPBearer()


# ============================================================================
# Password Hashing
# ============================================================================

def hash_password(password: str) -> str:
    """Hash a plain-text password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain-text password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


# ============================================================================
# JWT Token Management
# ============================================================================

def create_access_token(
    user_id: UUID,
    username: str,
    email: str,
    organization_id: UUID,
    role: str,
    is_superuser: bool = False,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token with organization context.

    Args:
        user_id: User's UUID
        username: User's username
        email: User's email
        organization_id: Current organization UUID
        role: User's role in this organization (admin, analyst, viewer)
        is_superuser: Whether user is a platform superuser
        expires_delta: Optional expiration time delta

    Returns:
        Encoded JWT token string
    """
    to_encode = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "organization_id": str(organization_id),
        "role": role,
        "is_superuser": is_superuser,
    }

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate a JWT token.

    Args:
        token: JWT token string

    Returns:
        Dict containing token payload

    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=401,
            detail=f"Could not validate credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ============================================================================
# API Key Management
# ============================================================================

def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key.

    Returns:
        tuple: (full_key, key_hash, key_prefix)
            - full_key: The actual key to show to user (once)
            - key_hash: SHA256 hash to store in database
            - key_prefix: First 12 chars for display (e.g., venti_sk_abc...)
    """
    # Generate random key: venti_sk_<32 random hex chars>
    random_part = secrets.token_hex(16)  # 32 hex chars
    full_key = f"venti_sk_{random_part}"

    # Hash the key for storage
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()

    # Extract prefix for display
    key_prefix = full_key[:12]  # "venti_sk_abc"

    return full_key, key_hash, key_prefix


def verify_api_key(key: str, db: Session) -> Optional[ApiKey]:
    """
    Verify an API key and return the ApiKey record if valid.

    Args:
        key: The API key string (e.g., "venti_sk_...")
        db: Database session

    Returns:
        ApiKey record if valid, None otherwise
    """
    # Hash the provided key
    key_hash = hashlib.sha256(key.encode()).hexdigest()

    # Look up in database
    api_key = db.query(ApiKey).filter(
        ApiKey.key_hash == key_hash,
        ApiKey.is_active == True
    ).first()

    if not api_key:
        return None

    # Check expiration
    if api_key.expires_at and api_key.expires_at < datetime.utcnow():
        return None

    # Update last_used_at
    api_key.last_used_at = datetime.utcnow()
    db.commit()

    return api_key


# ============================================================================
# Authentication Dependencies
# ============================================================================

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Dependency to get current authenticated user from JWT or API key.

    Returns user context with organization membership.
    """
    token = credentials.credentials

    # Try JWT first
    if not token.startswith("venti_sk_"):
        payload = decode_token(token)
        user_id = UUID(payload.get("sub"))
        organization_id = UUID(payload.get("organization_id"))

        # Verify user exists and is active
        user = db.query(User).filter(
            User.id == user_id,
            User.is_active == True,
            User.deleted_at == None
        ).first()

        if not user:
            raise HTTPException(status_code=401, detail="User not found or inactive")

        # Return context
        return {
            "user_id": user_id,
            "username": payload.get("username"),
            "email": payload.get("email"),
            "organization_id": organization_id,
            "role": payload.get("role"),
            "is_superuser": payload.get("is_superuser", False),
            "auth_type": "jwt"
        }

    # Try API key
    else:
        api_key = verify_api_key(token, db)
        if not api_key:
            raise HTTPException(status_code=401, detail="Invalid or expired API key")

        # Get organization
        organization = db.query(Organization).filter(
            Organization.id == api_key.organization_id
        ).first()

        if not organization or not organization.is_active:
            raise HTTPException(status_code=401, detail="Organization not found or inactive")

        # Return context (API keys have admin scope by default)
        return {
            "user_id": api_key.created_by,
            "username": f"api_key:{api_key.name}",
            "email": None,
            "organization_id": api_key.organization_id,
            "role": "admin",  # API keys have admin privileges
            "is_superuser": False,
            "auth_type": "api_key",
            "api_key_id": api_key.id,
            "scopes": api_key.scopes
        }


async def get_current_active_user(
    current_user: Dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """Dependency that ensures user is active."""
    return current_user


async def get_superuser(
    current_user: Dict = Depends(get_current_active_user)
) -> Dict[str, Any]:
    """Dependency that ensures user is a superuser."""
    if not current_user.get("is_superuser"):
        raise HTTPException(status_code=403, detail="Superuser access required")
    return current_user


# ============================================================================
# Permission Decorators
# ============================================================================

def require_role(allowed_roles: List[str]):
    """
    Decorator to require specific roles for an endpoint.

    Usage:
        @require_role(["admin", "analyst"])
        async def my_endpoint(current_user: Dict = Depends(get_current_user)):
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: Dict = None, **kwargs):
            if not current_user:
                raise HTTPException(status_code=401, detail="Authentication required")

            user_role = current_user.get("role")
            is_superuser = current_user.get("is_superuser", False)

            # Superusers bypass role checks
            if is_superuser:
                return await func(*args, current_user=current_user, **kwargs)

            # Check if user has allowed role
            if user_role not in allowed_roles:
                raise HTTPException(
                    status_code=403,
                    detail=f"Insufficient permissions. Required roles: {', '.join(allowed_roles)}"
                )

            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator


def require_scope(required_scopes: List[str]):
    """
    Decorator to require specific API key scopes.

    Only applies to API key authentication, not JWT.

    Usage:
        @require_scope(["write:scans"])
        async def my_endpoint(current_user: Dict = Depends(get_current_user)):
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: Dict = None, **kwargs):
            if not current_user:
                raise HTTPException(status_code=401, detail="Authentication required")

            # Only check scopes for API key auth
            if current_user.get("auth_type") != "api_key":
                return await func(*args, current_user=current_user, **kwargs)

            user_scopes = current_user.get("scopes", [])

            # Check if user has all required scopes
            if "admin:all" in user_scopes:
                return await func(*args, current_user=current_user, **kwargs)

            for scope in required_scopes:
                if scope not in user_scopes:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Insufficient scopes. Required: {', '.join(required_scopes)}"
                    )

            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator


# ============================================================================
# Organization Access Checks
# ============================================================================

def check_organization_access(
    user_id: UUID,
    organization_id: UUID,
    db: Session
) -> bool:
    """
    Check if user has access to an organization.

    Args:
        user_id: User's UUID
        organization_id: Organization's UUID
        db: Database session

    Returns:
        True if user has access, False otherwise
    """
    # Check if user is superuser
    user = db.query(User).filter(User.id == user_id).first()
    if user and user.is_superuser:
        return True

    # Check membership
    membership = db.query(OrganizationMembership).filter(
        OrganizationMembership.user_id == user_id,
        OrganizationMembership.organization_id == organization_id,
        OrganizationMembership.is_active == True
    ).first()

    return membership is not None


def get_user_role_in_org(
    user_id: UUID,
    organization_id: UUID,
    db: Session
) -> Optional[str]:
    """
    Get user's role in an organization.

    Args:
        user_id: User's UUID
        organization_id: Organization's UUID
        db: Database session

    Returns:
        Role string (admin, analyst, viewer) or None
    """
    membership = db.query(OrganizationMembership).filter(
        OrganizationMembership.user_id == user_id,
        OrganizationMembership.organization_id == organization_id,
        OrganizationMembership.is_active == True
    ).first()

    return membership.role if membership else None


# ============================================================================
# Audit Logging
# ============================================================================

async def log_audit_event(
    db: Session,
    organization_id: Optional[UUID],
    user_id: Optional[UUID],
    action: str,
    resource_type: str,
    resource_id: Optional[UUID] = None,
    details: Optional[Dict[str, Any]] = None,
    request: Optional[Request] = None
):
    """
    Log an audit event.

    Args:
        db: Database session
        organization_id: Organization UUID (None for platform-wide events)
        user_id: User UUID (None for system events)
        action: Action performed (e.g., "user.invited", "scan.created")
        resource_type: Type of resource (e.g., "user", "scan", "finding")
        resource_id: UUID of affected resource
        details: Additional context as JSON
        request: FastAPI Request object for IP/user agent extraction
    """
    ip_address = None
    user_agent = None

    if request:
        # Extract IP address
        if "x-forwarded-for" in request.headers:
            ip_address = request.headers["x-forwarded-for"].split(",")[0].strip()
        else:
            ip_address = request.client.host if request.client else None

        # Extract user agent
        user_agent = request.headers.get("user-agent")

    # Create audit log entry
    audit_entry = AuditLog(
        organization_id=organization_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        ip_address=ip_address,
        user_agent=user_agent
    )

    db.add(audit_entry)
    db.commit()


# ============================================================================
# Helper Functions
# ============================================================================

def get_user_organizations(user_id: UUID, db: Session) -> List[Dict[str, Any]]:
    """
    Get all organizations a user belongs to with their roles.

    Args:
        user_id: User's UUID
        db: Database session

    Returns:
        List of dicts with organization info and user's role
    """
    memberships = db.query(OrganizationMembership).filter(
        OrganizationMembership.user_id == user_id,
        OrganizationMembership.is_active == True
    ).all()

    orgs = []
    for membership in memberships:
        org = membership.organization
        if org and org.is_active:
            orgs.append({
                "organization_id": str(org.id),
                "name": org.name,
                "slug": org.slug,
                "tier": org.tier,
                "role": membership.role,
                "joined_at": membership.joined_at.isoformat() if membership.joined_at else None
            })

    return orgs


def switch_organization(
    user_id: UUID,
    new_organization_id: UUID,
    db: Session
) -> Optional[str]:
    """
    Generate a new JWT token for a different organization.

    Args:
        user_id: User's UUID
        new_organization_id: Target organization UUID
        db: Database session

    Returns:
        New JWT token string or None if user lacks access
    """
    # Check if user has access
    if not check_organization_access(user_id, new_organization_id, db):
        return None

    # Get user details
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return None

    # Get role in new organization
    role = get_user_role_in_org(user_id, new_organization_id, db)
    if not role:
        return None

    # Generate new token
    token = create_access_token(
        user_id=user.id,
        username=user.username,
        email=user.email,
        organization_id=new_organization_id,
        role=role,
        is_superuser=user.is_superuser
    )

    return token
