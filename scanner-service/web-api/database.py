"""
Database connection and session management for VentiAPI scan history.

This module provides PostgreSQL connection pooling and session management
for storing historical scan results, enabling trend analysis and comparison.

Week 2: Scan History & Trending
"""

import os
import logging
from typing import Generator, Optional
from contextlib import contextmanager

from sqlalchemy import create_engine, event, pool
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool

# Configure logging
logger = logging.getLogger(__name__)

# ============================================================================
# Database Configuration
# ============================================================================

# Database URL from environment (with sensible default for local development)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://rag_user:rag_pass@localhost:54320/ventiapi"
)

# Connection pool settings
POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "5"))
MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "10"))
POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "30"))
POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "3600"))  # 1 hour

# Enable SQL logging in development
SQL_ECHO = os.getenv("SQL_ECHO", "false").lower() == "true"

# ============================================================================
# SQLAlchemy Base
# ============================================================================

Base = declarative_base()

# ============================================================================
# Database Engine
# ============================================================================

def create_db_engine():
    """
    Create SQLAlchemy engine with connection pooling.

    Returns:
        Engine: SQLAlchemy engine instance
    """
    logger.info(f"Creating database engine for: {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else 'database'}")

    engine = create_engine(
        DATABASE_URL,
        poolclass=QueuePool,
        pool_size=POOL_SIZE,
        max_overflow=MAX_OVERFLOW,
        pool_timeout=POOL_TIMEOUT,
        pool_recycle=POOL_RECYCLE,
        pool_pre_ping=True,  # Verify connections before using
        echo=SQL_ECHO,
        future=True,  # Use SQLAlchemy 2.0 style
    )

    # Log connection pool events in debug mode
    if SQL_ECHO:
        @event.listens_for(engine, "connect")
        def receive_connect(dbapi_conn, connection_record):
            logger.debug("Database connection established")

        @event.listens_for(engine, "close")
        def receive_close(dbapi_conn, connection_record):
            logger.debug("Database connection closed")

    return engine


# Global engine instance
engine = None

def get_engine():
    """Get or create the global engine instance."""
    global engine
    if engine is None:
        engine = create_db_engine()
    return engine


# ============================================================================
# Session Factory
# ============================================================================

def create_session_factory():
    """
    Create SQLAlchemy session factory.

    Returns:
        sessionmaker: Session factory
    """
    return sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=get_engine(),
    )


# Global session factory
SessionLocal = create_session_factory()


# ============================================================================
# Session Dependency (for FastAPI)
# ============================================================================

def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency for database sessions.

    Usage:
        @app.get("/api/scans")
        def list_scans(db: Session = Depends(get_db)):
            return db.query(Scan).all()

    Yields:
        Session: Database session
    """
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """
    Context manager for database sessions (non-FastAPI usage).

    Usage:
        with get_db_context() as db:
            scan = db.query(Scan).first()

    Yields:
        Session: Database session
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception as e:
        logger.error(f"Database transaction error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


# ============================================================================
# Database Initialization
# ============================================================================

def init_db():
    """
    Initialize database tables.

    Note: In production, use Alembic migrations instead.
    This is a convenience function for development.
    """
    try:
        Base.metadata.create_all(bind=get_engine())
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise


def check_db_connection() -> bool:
    """
    Check if database connection is working.

    Returns:
        bool: True if connection successful, False otherwise
    """
    try:
        with get_db_context() as db:
            db.execute("SELECT 1")
        logger.info("Database connection check: OK")
        return True
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return False


# ============================================================================
# Graceful Shutdown
# ============================================================================

def close_db():
    """Close database connections gracefully."""
    global engine
    if engine:
        logger.info("Closing database connections...")
        engine.dispose()
        engine = None
        logger.info("Database connections closed")


# ============================================================================
# Health Check
# ============================================================================

async def database_health_check() -> dict:
    """
    Check database health for monitoring endpoints.

    Returns:
        dict: Health check result with status and details
    """
    try:
        with get_db_context() as db:
            result = db.execute("SELECT version()").fetchone()
            postgres_version = result[0] if result else "Unknown"

        return {
            "status": "healthy",
            "database": "PostgreSQL",
            "version": postgres_version,
            "connection_pool": {
                "size": POOL_SIZE,
                "max_overflow": MAX_OVERFLOW,
            }
        }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e)
        }


# ============================================================================
# Utility Functions
# ============================================================================

def generate_fingerprint(rule: str, endpoint: str, method: str) -> str:
    """
    Generate a consistent fingerprint for finding deduplication.

    Args:
        rule: OWASP API rule (e.g., 'API1')
        endpoint: API endpoint path
        method: HTTP method

    Returns:
        str: MD5 hash fingerprint
    """
    import hashlib
    content = f"{rule}:{endpoint}:{method}"
    return hashlib.md5(content.encode()).hexdigest()


# ============================================================================
# Module Initialization
# ============================================================================

# Log database configuration on import (not connection, just config)
logger.info(f"Database module loaded (Pool size: {POOL_SIZE}, Max overflow: {MAX_OVERFLOW})")

# Note: Don't create engine on import - let it be lazy-loaded
# This prevents connection attempts during module import
