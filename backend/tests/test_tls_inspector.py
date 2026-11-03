"""Tests for `app.modules.misconfiguration.tls_inspector`.

`check_tls_result` is pure (no I/O) and is tested with plain constructed
`TlsInspectionResult` fixtures - no real certificate or socket needed.

`_inspect_port`/`inspect_tls` are the one place this entire phase opens
a real socket, so they're tested against a REAL local TLS listener, not
a mock of `ssl`/`socket`/`cryptography` - per this project's own
established lesson (CLAUDE.md: "trust the live API's actual shape over
how it looks in a mock"). The repo already has one TLS-test-fixture
precedent (`test_http_prober.py`'s `test_self_signed_https_target_is_
still_probed`), but that one shells out to the `openssl` CLI and skips
if it's unavailable. This module's task explicitly asks for a
`cryptography`-native fixture instead (`x509.CertificateBuilder` + a
generated RSA key), so the cert-generation helper below is new and does
not depend on an external `openssl` binary - this is the first such
fixture in the repo.
"""

import socket
import ssl
import threading
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.modules.misconfiguration.tls_inspector import (
    EXPIRING_SOON_WINDOW,
    TLS_CANDIDATE_PORTS,
    WEAK_PROTOCOLS,
    TlsInspectionResult,
    _inspect_port,
    check_tls_result,
    inspect_tls,
)

# ---------------------------------------------------------------------------
# Fixture helpers: a real self-signed cert (built with `cryptography`, not
# openssl) + a real socket/ssl TLS listener serving it.
# ---------------------------------------------------------------------------


def _generate_self_signed_cert(
    tmp_path: Path,
    common_name: str = "127.0.0.1",
    not_valid_before: datetime | None = None,
    not_valid_after: datetime | None = None,
) -> tuple[Path, Path]:
    """Builds a throwaway self-signed cert/key pair directly with
    `cryptography` (subject == issuer by construction - exactly the
    `is_self_signed` condition under test) and writes both as PEM files,
    since `ssl.SSLContext.load_cert_chain` requires file paths. Returns
    (cert_path, key_path).
    """
    now = datetime.now(UTC)
    nvb = not_valid_before if not_valid_before is not None else now - timedelta(days=1)
    nva = not_valid_after if not_valid_after is not None else now + timedelta(days=365)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nvb)
        .not_valid_after(nva)
        .sign(private_key, hashes.SHA256())
    )

    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@contextmanager
def _tls_server(cert_path: Path, key_path: Path) -> Generator[int, None, None]:
    """Serves the given cert/key over a real TLS handshake on an
    ephemeral 127.0.0.1 port, in a background thread, for exactly one
    connection. No application data is exchanged - `_inspect_port` only
    needs the handshake and the peer certificate, so the server simply
    completes the handshake and then lets the connection close.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _serve() -> None:
        try:
            conn, _addr = listener.accept()
        except OSError:
            return
        try:
            with context.wrap_socket(conn, server_side=True) as tls_conn:
                try:
                    tls_conn.recv(1)
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            conn.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        listener.close()
        thread.join(timeout=5)


@contextmanager
def _non_tls_tcp_server() -> Generator[int, None, None]:
    """A plain TCP listener that accepts a connection and closes it
    without ever speaking TLS - used to prove a non-TLS port produces
    `None`, not a raised exception, from a real handshake attempt.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _serve() -> None:
        try:
            conn, _addr = listener.accept()
        except OSError:
            return
        conn.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        listener.close()
        thread.join(timeout=5)


def _unused_port() -> int:
    """Returns a port that is (almost certainly) not currently bound,
    by briefly binding to an OS-assigned ephemeral port and releasing
    it - the standard technique for a 'guaranteed nothing listening
    here' test target.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


# ---------------------------------------------------------------------------
# check_tls_result: pure function, constructed fixtures, no I/O.
# ---------------------------------------------------------------------------


def _result(
    *,
    port: int = 443,
    protocol_version: str | None = "TLSv1.3",
    subject: str | None = "CN=example.com",
    issuer: str | None = "CN=Some CA",
    not_valid_before: datetime | None = None,
    not_valid_after: datetime | None = None,
    is_self_signed: bool = False,
) -> TlsInspectionResult:
    return TlsInspectionResult(
        port=port,
        protocol_version=protocol_version,
        subject=subject,
        issuer=issuer,
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after,
        is_self_signed=is_self_signed,
    )


def test_check_tls_result_self_signed() -> None:
    result = _result(is_self_signed=True, subject="CN=self", issuer="CN=self")

    candidates = check_tls_result(result)

    check_ids = {c.check_id for c in candidates}
    assert "self-signed-cert" in check_ids
    self_signed = next(c for c in candidates if c.check_id == "self-signed-cert")
    assert self_signed.severity == "MEDIUM"


def test_check_tls_result_not_self_signed_no_candidate() -> None:
    result = _result(is_self_signed=False)

    candidates = check_tls_result(result)

    assert "self-signed-cert" not in {c.check_id for c in candidates}


def test_check_tls_result_expired_cert() -> None:
    expired_at = datetime.now(UTC) - timedelta(days=5)
    result = _result(not_valid_after=expired_at)

    candidates = check_tls_result(result)

    check_ids = {c.check_id for c in candidates}
    assert "expired-cert" in check_ids
    expired = next(c for c in candidates if c.check_id == "expired-cert")
    assert expired.severity == "HIGH"


def test_check_tls_result_expiring_soon_cert() -> None:
    expiring_at = datetime.now(UTC) + timedelta(days=10)
    result = _result(not_valid_after=expiring_at)

    candidates = check_tls_result(result)

    check_ids = {c.check_id for c in candidates}
    assert "expiring-soon-cert" in check_ids
    expiring = next(c for c in candidates if c.check_id == "expiring-soon-cert")
    assert expiring.severity == "LOW"
    assert "expired-cert" not in check_ids


def test_check_tls_result_expired_and_expiring_soon_are_mutually_exclusive() -> None:
    """An already-expired cert is trivially also 'within the next 30
    days' of now (any past date is), so the elif in check_tls_result is
    load-bearing: a cert that is both expired AND inside the
    expiring-soon window must produce only `expired-cert`, never both.
    """
    expired_at = datetime.now(UTC) - timedelta(days=1)
    assert expired_at < datetime.now(UTC) + EXPIRING_SOON_WINDOW  # sanity: inside the window too
    result = _result(not_valid_after=expired_at)

    candidates = check_tls_result(result)

    check_ids = [c.check_id for c in candidates]
    assert check_ids.count("expired-cert") == 1
    assert "expiring-soon-cert" not in check_ids


def test_check_tls_result_weak_protocol() -> None:
    far_future = datetime.now(UTC) + timedelta(days=400)
    for weak in WEAK_PROTOCOLS:
        result = _result(protocol_version=weak, not_valid_after=far_future)

        candidates = check_tls_result(result)

        check_ids = {c.check_id for c in candidates}
        assert "weak-tls-protocol" in check_ids, weak
        weak_candidate = next(c for c in candidates if c.check_id == "weak-tls-protocol")
        assert weak_candidate.severity == "HIGH"


def test_check_tls_result_strong_protocol_no_candidate() -> None:
    far_future = datetime.now(UTC) + timedelta(days=400)
    result = _result(protocol_version="TLSv1.3", not_valid_after=far_future)

    candidates = check_tls_result(result)

    assert "weak-tls-protocol" not in {c.check_id for c in candidates}


def test_check_tls_result_clean_result_produces_no_candidates() -> None:
    result = _result(
        protocol_version="TLSv1.3",
        subject="CN=example.com",
        issuer="CN=Trusted CA",
        is_self_signed=False,
        not_valid_before=datetime.now(UTC) - timedelta(days=30),
        not_valid_after=datetime.now(UTC) + timedelta(days=400),
    )

    candidates = check_tls_result(result)

    assert candidates == []


def test_check_tls_result_none_protocol_version_is_not_weak() -> None:
    # protocol_version=None happens when getpeercert() returned an empty
    # cert but the handshake still completed; `in WEAK_PROTOCOLS` must
    # not raise or misfire for this - it's just not a member.
    result = _result(protocol_version=None, not_valid_after=None)

    candidates = check_tls_result(result)

    assert candidates == []


def test_tls_candidate_ports_constant() -> None:
    assert TLS_CANDIDATE_PORTS == frozenset({443, 4443, 8443})


# ---------------------------------------------------------------------------
# _inspect_port / inspect_tls: real handshakes against a real listener.
# ---------------------------------------------------------------------------


def test_inspect_port_real_self_signed_handshake(tmp_path: Path) -> None:
    cert_path, key_path = _generate_self_signed_cert(tmp_path, common_name="127.0.0.1")

    with _tls_server(cert_path, key_path) as port:
        result = _inspect_port("127.0.0.1", port, timeout_seconds=3.0)

    assert result is not None
    assert result.port == port
    assert result.is_self_signed is True
    assert result.subject is not None and "127.0.0.1" in result.subject
    assert result.issuer == result.subject
    assert result.protocol_version is not None and result.protocol_version.startswith("TLSv1")
    assert result.not_valid_before is not None
    assert result.not_valid_after is not None


def test_inspect_port_real_handshake_feeds_check_tls_result(tmp_path: Path) -> None:
    """End-to-end: a real self-signed cert over a real handshake,
    fed into the pure check function, flags self-signed-cert.
    """
    cert_path, key_path = _generate_self_signed_cert(tmp_path, common_name="127.0.0.1")

    with _tls_server(cert_path, key_path) as port:
        result = _inspect_port("127.0.0.1", port, timeout_seconds=3.0)

    assert result is not None
    candidates = check_tls_result(result)
    assert any(c.check_id == "self-signed-cert" for c in candidates)


def test_inspect_port_no_listener_returns_none() -> None:
    port = _unused_port()

    result = _inspect_port("127.0.0.1", port, timeout_seconds=1.0)

    assert result is None


def test_inspect_port_non_tls_listener_returns_none() -> None:
    with _non_tls_tcp_server() as port:
        result = _inspect_port("127.0.0.1", port, timeout_seconds=2.0)

    assert result is None


def test_inspect_tls_concurrent_mix_of_real_and_dead_ports(tmp_path: Path) -> None:
    cert_path, key_path = _generate_self_signed_cert(tmp_path, common_name="127.0.0.1")
    dead_port = _unused_port()

    with _tls_server(cert_path, key_path) as live_port:
        results = inspect_tls("127.0.0.1", [live_port, dead_port], timeout_seconds=3.0)

    assert live_port in results
    assert dead_port not in results
    assert results[live_port].is_self_signed is True


def test_inspect_tls_returns_empty_dict_for_no_ports() -> None:
    assert inspect_tls("127.0.0.1", [], timeout_seconds=1.0) == {}
