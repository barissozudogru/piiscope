"""Database configuration and session management.

This module defines the SQLAlchemy engine and session factory used by
the API and Celery worker.  The connection string is defined in
`config.py`.  Sessions created from this factory must be closed
properly to avoid connection leaks.
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import settings

# Create the SQLAlchemy engine; pool_pre_ping ensures that dead
# connections are detected and recycled.
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    future=True,
)

# Declarative base class for models
Base = declarative_base()

# Session factory
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_db():
    """FastAPI dependency that yields a database session.

    Sessions are created on each request and closed automatically
    afterwards.  The generator pattern ensures that the session is
    closed even if an exception occurs.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
