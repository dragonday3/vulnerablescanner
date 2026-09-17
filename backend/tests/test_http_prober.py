import gzip
import shutil
import socket
import ssl
import subprocess
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from app.modules.fingerprinting.http_prober import (
    _TLS_HEURISTIC_PORTS,
    MAX_RESPONSE_BYTES,
    _parse_server_header,
    probe_services,
)


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


class _OversizedHandler(BaseHTTPRequestHandler):
    """Serves a plain (uncompressed) body well past MAX_RESPONSE_BYTES,
    with a `<title>` placed only after that boundary - used to prove the
    prober's body cap is actually enforced rather than merely documented.
    """

    def do_GET(self) -> None:
        padding = b"A" * (MAX_RESPONSE_BYTES * 3)
        body = padding + b"<title>Hidden Beyond Cap</title>"
        self.send_response_only(200)
        self.send_header("Server", "OversizedServer/9.9")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # keep test output quiet


class _GzipBombHandler(BaseHTTPRequestHandler):
    """Serves a gzip-compressed body whose DECOMPRESSED size is ~100x
    MAX_RESPONSE_BYTES, with a `<title>` placed at the very FRONT of the
    decompressed stream (well within the first MAX_RESPONSE_BYTES of the
    decompressed text, followed by ~100x-the-cap of padding) - this is
    deliberate, not incidental: it's what makes the test discriminate
    `aiter_raw()` from `aiter_bytes()`.

    The compressed body itself is small (under the cap), so a cap check
    applied to *raw* bytes (aiter_raw(), the correct behavior) never
    trips - the loop completes normally and the prober decodes the raw
    gzip bytes as text, which is garbage, so `title` comes back None. A
    regression to `aiter_bytes()` (transparent decompression) would grow
    `body` past the cap on largely the first yielded chunk and break out
    of the loop - but since the title sits in the first MAX_RESPONSE_BYTES
    of the *decompressed* stream, it would still be present in that
    truncated `body[:MAX_RESPONSE_BYTES]` slice and get matched. Putting
    the title past the decompressed boundary instead (as an earlier draft
    of this test did) would make it invisible to BOTH implementations
    equally, since the cap-slice truncates before the title either way -
    silently defeating the whole point of this test. Front-loading the
    title is what makes `title is None` a real regression lock rather
    than a vacuous assertion.
    """

    def do_GET(self) -> None:
        title = b"<title>Hidden Beyond Decompression Cap</title>"
        padding = b"A" * (MAX_RESPONSE_BYTES * 100)
        decompressed = title + padding
        body = gzip.compress(decompressed)
        self.send_response_only(200)
        self.send_header("Server", "GzipBombServer/1.0")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # keep test output quiet


@contextmanager
def _running_http_server(
    handler_cls: type[BaseHTTPRequestHandler],
) -> Generator[int, None, None]:
    """Starts a stdlib HTTPServer on 127.0.0.1 with an OS-assigned free
    port, avoiding (on the astronomically unlikely chance of a collision)
    one of the module's own `_TLS_HEURISTIC_PORTS`, since these test
    servers always serve plain HTTP and an https-first attempt against one
    would fail the TLS handshake.
    """
    server: HTTPServer | None = None
    for _ in range(5):
        candidate = HTTPServer(("127.0.0.1", 0), handler_cls)
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


@pytest.fixture()
def http_fixture_server() -> Generator[int, None, None]:
    with _running_http_server(_FixtureHandler) as port:
        yield port


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


def test_response_larger_than_cap_is_truncated_before_hidden_title() -> None:
    # The `<title>` in _OversizedHandler's body sits well past
    # MAX_RESPONSE_BYTES; if the streaming cap weren't actually enforced
    # (rather than just documented), the full body would be read and this
    # title would be found. Its absence is the proof the cap did its job.
    with _running_http_server(_OversizedHandler) as port:
        results = probe_services("127.0.0.1", [port], timeout_seconds=2.0)

    assert port in results
    result = results[port]
    assert result.status_code == 200
    assert result.server_header == "OversizedServer/9.9"
    assert result.title is None


def test_gzip_compressed_oversized_body_is_not_decompressed_past_cap() -> None:
    """Regression lock for the decompression-amplification fix: the prober
    must read wire (compressed) bytes via `aiter_raw()`, never
    transparently-decompressed bytes via `aiter_bytes()`. A hostile server
    that ignores `Accept-Encoding: identity` and gzip-compresses its
    response anyway must not be able to smuggle a body ~100x
    MAX_RESPONSE_BYTES past the cap by exploiting decompression - the
    hidden title, placed only past that decompressed boundary, must not be
    found, the same "hidden title past the boundary isn't found" technique
    `test_response_larger_than_cap_is_truncated_before_hidden_title` uses
    for the plain (uncompressed) case.
    """
    with _running_http_server(_GzipBombHandler) as port:
        results = probe_services("127.0.0.1", [port], timeout_seconds=2.0)

    assert port in results
    result = results[port]
    assert result.status_code == 200
    assert result.server_header == "GzipBombServer/1.0"
    assert result.title is None


def test_dripping_response_is_bounded_by_total_operation_deadline() -> None:
    """Guards the fix for the final-review finding that `httpx.Timeout`
    only bounds each *individual* I/O operation, not the request as a
    whole: a target that sends data slower than any single per-operation
    timeout - each new byte arriving just before the read timeout would
    fire - previously could stall a probe indefinitely (hours, in the
    worst case), since no individual operation ever actually timed out.
    `asyncio.wait_for(..., timeout=timeout_seconds * 3)` in `_probe_port`
    adds the missing total-operation deadline this test proves is in
    effect.

    The server here accepts a connection, sends a minimal valid HTTP
    status line, then "drips" one header byte every ~0.25s - never
    completing the headers (no blank-line terminator ever arrives) - for
    far longer (~50s) than this test's own configured timeout, so nothing
    about the drip loop itself ends the probe early; only the wrapped
    total-operation deadline can. A short, test-specific `timeout_seconds`
    keeps the *test* fast; the assertion is that `probe_services` returns
    in a bounded time (a small multiple of that short timeout), not that
    it hangs.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def _accept_and_drip() -> None:
        listener.settimeout(5.0)
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        try:
            conn.sendall(b"HTTP/1.1 200 OK\r\n")
            # Drip one header byte at a time - each arrives comfortably
            # before any single per-operation read timeout could fire, so
            # only a total-operation deadline can end this. Deliberately
            # long (~50s at 0.25s/byte) relative to the test's own
            # `short_timeout` below, so the drip loop never finishes on
            # its own within the test.
            drip = b"X-Pad: " + (b"a" * 200) + b"\r\n"
            for byte in drip:
                if stop.is_set():
                    return
                try:
                    conn.sendall(bytes([byte]))
                except OSError:
                    return
                stop.wait(timeout=0.25)
        finally:
            conn.close()

    thread = threading.Thread(target=_accept_and_drip, daemon=True)
    thread.start()
    try:
        short_timeout = 0.5
        started = time.monotonic()
        results = probe_services("127.0.0.1", [port], timeout_seconds=short_timeout)
        elapsed = time.monotonic() - started

        assert results == {}
        # Bounded by the total-operation deadline (timeout_seconds * 3),
        # plus generous slack for scheduler/CI jitter - proves the call
        # returned rather than hanging for anywhere near the drip loop's
        # full ~50s duration.
        assert elapsed < (short_timeout * 3) + 5.0
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=5)


def test_parse_server_header_without_extrainfo() -> None:
    # Companion to test_probes_and_parses_known_server's
    # "Apache/2.4.41 (Ubuntu)"-with-extrainfo case: the plain
    # "product/version" shape, with nothing trailing, must leave
    # extrainfo as None rather than an empty string or a parse error.
    product, version, extrainfo = _parse_server_header("nginx/1.24.0")

    assert product == "nginx"
    assert version == "1.24.0"
    assert extrainfo is None


def test_self_signed_https_target_is_still_probed(tmp_path: Path) -> None:
    """Final-review finding #3: with httpx's default `verify=True`, every
    probe of a `_TLS_HEURISTIC_PORTS` port (443/4443/8443) against a
    self-signed certificate - the overwhelmingly common case for the
    internal/lab targets this scanner is built to fingerprint - raises an
    SSL verification error, which `_probe_port`'s per-port exception
    handler swallows, silently omitting the port from results. `verify=
    False` on the `AsyncClient` (module-level, in `_probe_services_async`)
    fixes this. This test proves an HTTPS target with a self-signed cert
    is still successfully probed rather than silently dropped.
    """
    if shutil.which("openssl") is None:
        pytest.skip("openssl CLI not available in this environment")

    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    # Must be one of _TLS_HEURISTIC_PORTS so the prober tries https first;
    # 8443 (unlike 443) doesn't require elevated privileges to bind.
    port = 8443
    server = HTTPServer(("127.0.0.1", port), _FixtureHandler)
    server.socket = ssl_context.wrap_socket(server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        results = probe_services("127.0.0.1", [port], timeout_seconds=3.0)
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert port in results
    result = results[port]
    assert result.scheme == "https"
    assert result.status_code == 200
    assert result.server_header == "TestServer/1.2.3 (TestOS)"
