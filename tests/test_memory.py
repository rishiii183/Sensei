"""Persistence tests for SQLite database and SenseiRepository."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sensei.memory.database import Base
from sensei.memory.repository import SenseiRepository


def _create_in_memory_repo() -> SenseiRepository:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    import sensei.memory.models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    return SenseiRepository(db=Session())


def test_session_scope_finding_and_report_persistence():
    repo = _create_in_memory_repo()

    session = repo.create_session(name="Juice Shop Audit", mode="COPILOT")
    assert session.id

    repo.add_target_scope(session.id, target="http://localhost:3000", is_authorized=True)
    scopes = repo.get_scopes(session.id)
    assert len(scopes) == 1
    assert scopes[0].target == "http://localhost:3000"

    repo.save_plan(
        session_id=session.id,
        objective="Audit website",
        steps=[{"description": "HTTP audit", "tool_name": "http_audit", "risk_level": "LOW"}],
    )

    repo.save_finding(
        session_id=session.id,
        finding_id="SEC-HEADER-CSP-MISSING",
        title="Missing CSP",
        description="CSP header missing",
        severity="MEDIUM",
        affected_asset="http://localhost:3000",
        evidence="Header absent",
    )
    findings = repo.get_findings(session.id)
    assert len(findings) == 1
    assert findings[0].finding_id == "SEC-HEADER-CSP-MISSING"

    repo.save_report(
        session_id=session.id,
        format_name="markdown",
        title="Test Report",
        content="# Report",
        file_path="reports/test.md",
    )
    reports = repo.get_reports(session.id)
    assert len(reports) == 1

    # Resume check
    resumed = repo.get_session(session.id)
    assert resumed is not None
    assert resumed.name == "Juice Shop Audit"
