"""End-to-end LangGraph orchestration, budget, and reporting tests."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sensei.agent.llm import BudgetExceededError, CostTracker, SenseiLLMClient
from sensei.agent.orchestrator import SenseiOrchestrator
from sensei.config import SenseiConfig
from sensei.memory.database import Base
from sensei.memory.repository import SenseiRepository
from sensei.reporting.generator import ReportGenerator
from sensei.security.scope import TargetScope, get_scope_registry


class MockAppHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "MockJuiceShop/1.0")
        self.end_headers()
        self.wfile.write(b"<h1>Mock Authorized Test App</h1>")

    def log_message(self, format, *args):
        return


def _in_memory_repo() -> SenseiRepository:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    import sensei.memory.models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    return SenseiRepository(db=Session())


def test_orchestrator_blocks_unauthorized_target():
    get_scope_registry().clear()
    repo = _in_memory_repo()
    llm = SenseiLLMClient(SenseiConfig(openai_api_key=None, groq_api_key=None))
    orchestrator = SenseiOrchestrator(repo=repo, llm_client=llm)

    state = orchestrator.run_instruction("Audit https://unauthorized.example.org for vulnerabilities")
    assert state["target_authorized"] is False
    assert "Authorization required" in (state.get("error") or "")
    assert state.get("report") is None


def test_orchestrator_end_to_end_authorized_assessment(tmp_path: Path):
    get_scope_registry().clear()
    server = HTTPServer(("127.0.0.1", 0), MockAppHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    target_url = f"http://127.0.0.1:{port}"
    get_scope_registry().add_scope(TargetScope(target=target_url, is_authorized=True))

    try:
        repo = _in_memory_repo()
        llm = SenseiLLMClient(SenseiConfig(openai_api_key=None, groq_api_key=None))
        orchestrator = SenseiOrchestrator(
            repo=repo,
            llm_client=llm,
            approval_callback=lambda step, reason: True,
        )

        state = orchestrator.run_instruction(
            f"Perform a security assessment of my authorized test website {target_url}."
        )
        assert state["target_authorized"] is True
        assert state.get("error") is None
        assert state.get("plan") is not None
        assert len(state["validated_findings"]) >= 1
        assert state.get("report") is not None
        assert "Security Mentor" in state["mentor_guidance"]

        # Verify Markdown, JSON, and HTML export
        gen = ReportGenerator(repo=repo)
        md_path = gen.save_report(state["report"], fmt="markdown", reports_dir=tmp_path)
        json_path = gen.save_report(state["report"], fmt="json", reports_dir=tmp_path)
        html_path = gen.save_report(state["report"], fmt="html", reports_dir=tmp_path)

        assert md_path.exists()
        assert json_path.exists()
        assert html_path.exists()
        assert "SEC-HEADER-CSP-MISSING" in md_path.read_text(encoding="utf-8")
    finally:
        server.shutdown()
        server.server_close()


def test_budget_tracker_enforces_limits():
    tracker = CostTracker(token_budget=100, cost_budget=0.05)
    tracker.record_usage(prompt_tokens=60, completion_tokens=50, cost_usd=0.01)
    with pytest.raises(BudgetExceededError):
        tracker.check_budget()

    tracker.budget_override_approved = True
    tracker.check_budget()


def test_groq_provider_selection():
    cfg = SenseiConfig(openai_api_key=None, groq_api_key="test-groq-dummy-key")
    client = SenseiLLMClient(cfg)
    status = client.get_status()
    assert status.active_provider == "groq"
    assert status.groq_configured is True
    assert status.active_model == cfg.groq_model
