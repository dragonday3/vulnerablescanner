import socket
import threading
import time
from collections.abc import Generator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.modules.fingerprinting.http_prober import _TLS_HEURISTIC_PORTS, probe_services


class _FixtureHandler(BaseHTTPRequestHandler):
    """Serves one canned HTML response with a known `Server` header."""

    # BaseHTTPRequestHandler.send_response() would inject its own default
    # "Server: BaseHTTP/... Python/..." header automatically; using
    # send_response_only() instead lets this handler set exactly one
    # `Server` header, matching the known value the test asserts against.
    def do_GET(self) -> None:
        body = b"<html><head><title>  Hello   Test   Server  </title></head><body></body></html>"
        self.send_response_only(200)
        self.send_header("Server", "TestServer/1.2.3 (TestOS)")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # keep test output quiet


@pytest.fixture()
def http_fixture_server() -> Generator[int, None, None]:
    """Starts a stdlib HTTPServer on 127.0.0.1 with an OS-assigned free
    port, avoiding (on the astronomically unlikely chance of a collision)
    one of the module's own `_TLS_HEURISTIC_PORTS`, since this fixture
    always serves plain HTTP and an https-first attempt against it would
    fail the TLS handshake.
    """
    server: HTTPServer | None = None
    for _ in range(5):
        candidate = HTTPServer(("127.0.0.1", 0), _FixtureHandler)
        if candidate.server_address[1] in _TLS_HEURISTIC_PORTS:
            candidate.server_close()
            continue
        server = candidate
        break
    assert server is not None, "failed to bind a non-TLS-heuristic test port"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_probes_and_parses_known_server(http_fixture_server: int) -> None:
    port = http_fixture_server

    results = probe_services("127.0.0.1", [port], timeout_seconds=2.0)

    assert port in results
    result = results[port]
    assert result.port == port
    assert result.scheme == "http"
    assert result.status_code == 200
    assert result.server_header == "TestServer/1.2.3 (TestOS)"
    assert result.product == "TestServer"
    assert result.version == "1.2.3"
    assert result.extrainfo == "(TestOS)"
    assert result.title == "Hello Test Server"
    assert result.headers.get("server") == "TestServer/1.2.3 (TestOS)"


def test_closed_port_is_absent_without_raising() -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    results = probe_services("127.0.0.1", [closed_port], timeout_seconds=1.0)

    assert results == {}


def test_never_responding_socket_is_absent_and_bounded_by_timeout() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def _accept_and_stall() -> None:
        listener.settimeout(5.0)
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        # Accept the connection but deliberately never write a response,
        # holding it open until the test tears it down.
        try:
            stop.wait(timeout=5.0)
        finally:
            conn.close()

    thread = threading.Thread(target=_accept_and_stall, daemon=True)
    thread.start()
    try:
        # A short, test-specific timeout keeps this test fast rather than
        # waiting on the module's own (longer) HTTP_PROBE_TIMEOUT_SECONDS
        # default.
        short_timeout = 0.5
        started = time.monotonic()
        results = probe_services("127.0.0.1", [port], timeout_seconds=short_timeout)
        elapsed = time.monotonic() - started

        assert results == {}
        # Generous multiple of the configured timeout, not an exact bound,
        # to absorb scheduler/CI jitter while still proving the call didn't
        # hang indefinitely.
        assert elapsed < short_timeout + 5.0
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=5)
