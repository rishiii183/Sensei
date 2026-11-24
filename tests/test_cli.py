"""CLI tests using Typer CliRunner."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typer.testing import CliRunner
from sensei.cli import app
from sensei.config import reset_config
from sensei.memory.database import reset_db
from sensei.security.scope import get_scope_registry

runner = CliRunner()


class CliTestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        return


def test_cli_help_tools_doctor_history():
    res_help = runner.invoke(app, ["--help"])
    assert res_help.exit_code == 0
    assert "Sensei" in res_help.stdout

    res_tools = runner.invoke(app, ["tools", "list"])
    assert res_tools.exit_code == 0
    assert "http_audit" in res_tools.stdout
    assert "nuclei" in res_tools.stdout

    res_doctor = runner.invoke(app, ["doctor"])
    assert res_doctor.exit_code == 0
    assert "OpenAI API Key" in res_doctor.stdout

    res_history = runner.invoke(app, ["history"])
    assert res_history.exit_code == 0


def test_cli_run_authorized_target(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'cli_test.db'}")
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("OPENAI_API_KEY", "")
    reset_config()
    reset_db()
    get_scope_registry().clear()

    server = HTTPServer(("127.0.0.1", 0), CliTestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        target = f"http://127.0.0.1:{port}"
        res = runner.invoke(
            app,
            [
                "run",
                "Audit my authorized test environment",
                "--target",
                target,
                "--authorize",
                "--yes",
            ],
        )
        assert res.exit_code == 0
        assert "Security Assessment Report" in res.stdout
    finally:
        server.shutdown()
        server.server_close()
