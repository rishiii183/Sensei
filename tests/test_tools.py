"""Unit and integration tests for ToolRegistry, NucleiAdapter, and HttpAuditAdapter."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch
from sensei.tools.adapters.http_audit import HttpAuditAdapter
from sensei.tools.adapters.nuclei import NucleiAdapter
from sensei.tools.registry import ToolRegistry


class VulnerableTestHandler(BaseHTTPRequestHandler):
    """Minimal local HTTP server simulating missing security headers and exposed files."""

    def do_GET(self):
        if self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=test_secret_value\n")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "TestServer/1.0")
        self.send_header("X-Powered-By", "Express")
        self.send_header("Set-Cookie", "session=abc123; Path=/")
        self.end_headers()
        self.wfile.write(b"<html><body>Local Test App</body></html>")

    def log_message(self, format, *args):
        return


def test_tool_registry_discovers_core_tools():
    registry = ToolRegistry()
    names = {t.name for t in registry.list_all()}
    assert {"http_audit", "nuclei", "nmap", "semgrep", "trivy", "gitleaks"}.issubset(names)
    assert registry.get("http_audit").check_availability() is True


def test_nuclei_input_validation_and_missing_binary():
    adapter = NucleiAdapter()
    validated = adapter.validate_input(
        {"target": "localhost:3000", "severity": "info,critical,low", "tags": "cve,tech;rm -rf"}
    )
    assert validated["target"] == "http://localhost:3000"
    # Critical severity filtered out of default safe set
    assert "critical" not in validated["severity"]
    # Shell metacharacters stripped from tags
    assert ";" not in validated["tags"]

    with patch("shutil.which", return_value=None):
        output = adapter.execute({"target": "http://localhost:3000"})
        assert not output.success
        assert "not installed or available" in (output.error_message or "")


def test_http_audit_against_local_server():
    server = HTTPServer(("127.0.0.1", 0), VulnerableTestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        adapter = HttpAuditAdapter()
        output = adapter.execute({"target": f"http://127.0.0.1:{port}"})
        assert output.success
        finding_ids = {f.finding_id for f in output.findings}
        assert "SEC-HEADER-CSP-MISSING" in finding_ids
        assert "SEC-HEADER-XFO-MISSING" in finding_ids
        assert "SEC-INFO-DISCLOSURE-BANNER" in finding_ids
        assert "SEC-COOKIE-HTTPONLY-MISSING-session" in finding_ids
        assert "SEC-EXPOSURE-_env" in finding_ids
    finally:
        server.shutdown()
        server.server_close()
