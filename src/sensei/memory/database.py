"""SQLite database initialization and session management using SQLAlchemy."""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session
from sensei.config import get_config

Base = declarative_base()

_engine = None
_SessionFactory = None


def get_engine():
    """Get or create SQLAlchemy engine."""
    global _engine
    if _engine is None:
        config = get_config()
        db_url = config.database_url
        # If relative sqlite URL, resolve cleanly
        _engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False} if "sqlite" in db_url else {},
            echo=False,
        )
    return _engine


def get_db_session():
    """Create a new database session."""
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _SessionFactory()


def init_db() -> None:
    """Create all database tables if they do not exist."""
    engine = get_engine()
    # Import all models to ensure registered on Base.metadata
    import sensei.memory.models  # noqa: F401
    Base.metadata.create_all(bind=engine)


def reset_db() -> None:
    """Reset cached engine and session factory (useful in tests)."""
    global _engine, _SessionFactory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionFactory = None
