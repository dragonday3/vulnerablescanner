"""The one new active network-probe surface Phase 6 introduces: a
bounded, best-effort TLS handshake against candidate TLS ports, reading
the peer certificate *without* validating it (that's the entire point -
normal validation would reject exactly the self-signed/expired certs
this module exists to flag).

Mirrors `fingerprinting/http_prober.py`'s security posture: a genuine
per-connection timeout, no credentials sent, passive evidence only.
Unlike `http_prober.py` (asyncio), this uses a `ThreadPoolExecutor` over
plain blocking sockets - there's no async TLS handshake primitive in the
stdlib, so threads are the right concurrency primitive here.

Deliberately independent of `fingerprinting/http_prober.py`:
`TLS_CANDIDATE_PORTS` is its own constant, not an import of that
module's private `_TLS_HEURISTIC_PORTS` (see PLAN_6.md's no-touch-other-
modules rule / CLAUDE.md's discovery/fingerprinting separation
principle, extended to this module).

`_inspect_port` is the only place this entire phase opens a socket. It
must never be called from anywhere except `inspect_tls` below, and it
must never raise - any failure (refused connection, non-TLS port,
timeout, unparseable cert) is swallowed and turned into `None` or a
partial result.
"""

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509

from app.modules.misconfiguration.checks import MisconfigCandidate

# Deliberately an independent copy, not an import of
# fingerprinting.http_prober's private _TLS_HEURISTIC_PORTS - see
# PLAN_6.md's no-touch-other-modules rule. Extended at call time (in
# analyzer.py) with any Service whose service_name suggests TLS on a
# non-standard port.
TLS_CANDIDATE_PORTS: frozenset[int] = frozenset({443, 4443, 8443})

TLS_PROBE_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_WORKERS = 10
EXPIRING_SOON_WINDOW = timedelta(days=30)
WEAK_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})


@dataclass(frozen=True)
class TlsInspectionResult:
    port: int
    protocol_version: str | None  # ssl_socket.version(), e.g. "TLSv1.3"
    subject: str | None  # RFC4514 string, e.g. "CN=example.com"
    issuer: str | None
    not_valid_before: datetime | None
    not_valid_after: datetime | None
    is_self_signed: bool  # subject == issuer (as parsed Name objects)


def _inspect_port(host: str, port: int, timeout_seconds: float) -> TlsInspectionResult | None:
    """One port, one blocking TLS handshake, verify disabled on purpose
    (see module docstring: the entire point is to inspect certs normal
    validation would reject). `timeout_seconds` passed to
    `socket.create_connection` bounds connect AND the handshake itself
    (both happen before this function does anything else - there is no
    subsequent data read to need a separate total-operation deadline the
    way http_prober.py's body-streaming does). Any failure (refused,
    reset, non-TLS port, timeout) returns None - never raises. This
    function makes the only new outbound network call this phase adds;
    it must never be called from anywhere except inspect_tls below.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Same reasoning as CERT_NONE just above: this module sends no
    # credentials and inspects certificates purely as passive evidence
    # (mirroring http_prober.py's verify=False posture), so there is no
    # security reason to refuse a legacy-TLS handshake. PROTOCOL_TLS_CLIENT
    # otherwise defaults to minimum_version=TLSv1_2 and a SECLEVEL 2 cipher
    # policy, which would make the handshake itself fail against a server
    # limited to TLS 1.1/1.0 or older ciphers - silently producing zero
    # findings for exactly the hosts the weak-tls-protocol check exists to
    # flag. Refusing the handshake would hide the misconfiguration, not
    # protect against it.
    context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    context.set_ciphers("ALL:@SECLEVEL=0")
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)
                protocol_version = tls_sock.version()
    except Exception:
        return None
    if der_cert is None:
        return TlsInspectionResult(port, protocol_version, None, None, None, None, False)
    try:
        cert = x509.load_der_x509_certificate(der_cert)
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        return TlsInspectionResult(
            port=port,
            protocol_version=protocol_version,
            subject=subject,
            issuer=issuer,
            not_valid_before=cert.not_valid_before_utc,
            not_valid_after=cert.not_valid_after_utc,
            is_self_signed=(cert.subject == cert.issuer),
        )
    except Exception:
        # Cert fetched but unparseable (corrupt/unsupported) - still a
        # real, if partial, result: protocol_version alone is still
        # useful to check_tls_result below.
        return TlsInspectionResult(port, protocol_version, None, None, None, None, False)


def inspect_tls(
    host: str,
    ports: list[int],
    timeout_seconds: float = TLS_PROBE_TIMEOUT_SECONDS,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> dict[int, TlsInspectionResult]:
    """Sync, thread-pool-concurrent (not asyncio - plain blocking
    socket/ssl, mirroring http_prober.py's concurrency *shape* with
    threads instead of coroutines since there's no async ssl handshake
    primitive in the stdlib). Per-port failures are swallowed inside
    _inspect_port; this function itself only raises for genuine misuse.
    """
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        results = pool.map(lambda p: _inspect_port(host, p, timeout_seconds), ports)
    return {r.port: r for r in results if r is not None}


def check_tls_result(result: TlsInspectionResult) -> list[MisconfigCandidate]:
    """Pure function over an already-fetched TlsInspectionResult - the
    network I/O (inspect_tls above) and the check logic are deliberately
    separate, same split as tls_inspector vs. checks.py for the other
    two families. Never raises.
    """
    candidates: list[MisconfigCandidate] = []

    if result.is_self_signed:
        candidates.append(
            MisconfigCandidate(
                check_id="self-signed-cert",
                title="Self-signed TLS certificate",
                severity="MEDIUM",
                description=(
                    f"The TLS certificate presented on port {result.port} is "
                    "self-signed (subject and issuer are identical), so it "
                    "cannot be validated by a standard certificate chain."
                ),
                evidence={
                    "port": result.port,
                    "subject": result.subject,
                    "issuer": result.issuer,
                },
            )
        )

    now = datetime.now(UTC)
    if result.not_valid_after is not None and result.not_valid_after < now:
        candidates.append(
            MisconfigCandidate(
                check_id="expired-cert",
                title="Expired TLS certificate",
                severity="HIGH",
                description=(
                    f"The TLS certificate presented on port {result.port} "
                    f"expired on {result.not_valid_after.isoformat()}."
                ),
                evidence={
                    "port": result.port,
                    "not_valid_after": result.not_valid_after.isoformat(),
                },
            )
        )
    elif result.not_valid_after is not None and result.not_valid_after < now + EXPIRING_SOON_WINDOW:
        candidates.append(
            MisconfigCandidate(
                check_id="expiring-soon-cert",
                title="TLS certificate expiring soon",
                severity="LOW",
                description=(
                    f"The TLS certificate presented on port {result.port} "
                    f"expires on {result.not_valid_after.isoformat()}, within "
                    f"the next {EXPIRING_SOON_WINDOW.days} days."
                ),
                evidence={
                    "port": result.port,
                    "not_valid_after": result.not_valid_after.isoformat(),
                },
            )
        )

    if result.protocol_version in WEAK_PROTOCOLS:
        candidates.append(
            MisconfigCandidate(
                check_id="weak-tls-protocol",
                title="Weak TLS protocol version negotiated",
                severity="HIGH",
                description=(
                    f"Port {result.port} negotiated {result.protocol_version}, "
                    "a deprecated/weak protocol version."
                ),
                evidence={
                    "port": result.port,
                    "protocol_version": result.protocol_version,
                },
            )
        )

    return candidates
