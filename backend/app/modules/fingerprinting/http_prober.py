"""Best-effort HTTP header/title probing for native-scanner-discovered
open ports that look like they serve HTTP(S).

Deliberately narrow in scope (see PLAN_3.md): a curated port allowlist,
one scheme attempt per port (no dual-scheme fallback), a short per-request
timeout distinct from the overall scan timeout, no redirect-following
(SSRF hygiene), and a bounded response-body read. Failure to probe an
individual port is swallowed here and simply omits that port from the
returned dict — callers (app.workers.tasks) never treat an empty/partial
result as an error.

The per-request timeout is enforced twice: `httpx.Timeout(timeout_seconds)`
bounds each individual I/O operation (connect/read/write/pool), and
`asyncio.wait_for` in `_probe_port` additionally bounds the *whole*
request/response cycle for a port to `timeout_seconds * 3` - a true
total-operation deadline. The per-operation bound alone is not sufficient:
a target that trickles bytes just under each per-operation timeout would
otherwise never trip any single timeout and could stall a probe (and thus
the whole enrichment pass) indefinitely.
"""

import asyncio
import re
from collections.abc import Iterable
from dataclasses import dataclass

import httpx

# Curated allowlist: the ports PLAN_3.md calls out explicitly, unioned
# with every port in modules.discovery.common_ports.PORT_NAMES whose name
# suggests a general-purpose web server (http/https/http-alt/http-proxy),
# hand-checked to exclude lookalikes that speak HTTP-ish protocols but
# aren't general web servers (e.g. 593 "http-rpc-epmap", 5985 "winrm").
WEB_PORTS: frozenset[int] = frozenset(
    {
        80,
        443,
        3000,
        4443,
        4567,
        5000,
        5001,
        8000,
        8008,
        8080,
        8081,
        8088,
        8090,
        8222,
        8443,
        8888,
        9000,
        9999,
    }
)

# Ports where an HTTPS attempt is tried first instead of HTTP.
_TLS_HEURISTIC_PORTS: frozenset[int] = frozenset({443, 4443, 8443})

HTTP_PROBE_TIMEOUT_SECONDS = 3.0
MAX_RESPONSE_BYTES = 8192
DEFAULT_MAX_CONCURRENCY = 10

# Bounded, case-insensitive, dotall match against the (already size-capped)
# response body text; `.*?` is non-greedy so a malformed/huge body with no
# closing tag can't force pathological backtracking - it simply fails to
# match, and the body was already capped to MAX_RESPONSE_BYTES anyway.
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Light heuristic for the `Server` response header, e.g.:
#   "nginx/1.24.0"           -> product="nginx", version="1.24.0"
#   "Apache/2.4.41 (Ubuntu)" -> product="Apache", version="2.4.41", extrainfo="(Ubuntu)"
# Anything that doesn't match this `product/version [extrainfo]` shape is
# left unparsed (product=version=extrainfo=None) - the raw header string is
# always preserved separately by the caller regardless of parse success.
_SERVER_HEADER_RE = re.compile(r"^(?P<product>[^\s/]+)/(?P<version>\S+)(?:\s+(?P<extrainfo>.*))?$")


@dataclass(frozen=True)
class HttpProbeResult:
    port: int
    scheme: str
    status_code: int
    server_header: str | None
    product: str | None  # best-effort parse of server_header
    version: str | None  # best-effort parse of server_header
    extrainfo: str | None  # best-effort parse remainder, if any
    title: str | None
    headers: dict[str, str]


def _parse_server_header(value: str) -> tuple[str | None, str | None, str | None]:
    """Best-effort split of a `Server` header into (product, version, extrainfo).

    Returns (None, None, None) if the header doesn't match the common
    `product/version [extrainfo]` shape - the raw header is never lost,
    since callers always keep it separately as `server_header`/evidence.
    """
    match = _SERVER_HEADER_RE.match(value.strip())
    if match is None:
        return None, None, None
    return match.group("product"), match.group("version"), match.group("extrainfo")


def _extract_title(body_text: str) -> str | None:
    match = _TITLE_RE.search(body_text)
    if match is None:
        return None
    collapsed = " ".join(match.group(1).split())
    return collapsed[:200] or None


async def _probe_port_body(
    client: httpx.AsyncClient,
    host: str,
    port: int,
) -> HttpProbeResult | None:
    """The actual per-port probe work, factored out of `_probe_port` so it
    can be wrapped in a total-operation deadline (`asyncio.wait_for`) by the
    caller - see `_probe_port` for why that wrapping is necessary.
    """
    scheme = "https" if port in _TLS_HEURISTIC_PORTS else "http"
    url = f"{scheme}://{host}:{port}/"

    body = b""
    # Ask for an uncompressed response (most servers honor this and
    # skip compression entirely, so title extraction works on the
    # common case), but don't *rely* on the target being honest:
    # `aiter_raw()` below reads wire bytes with no transparent
    # decompression, so MAX_RESPONSE_BYTES is a real bound on bytes
    # pulled into memory even against a hostile server that sends
    # `Content-Encoding: gzip` anyway (a small compressed payload
    # decompressing to a huge body - "decompression amplification" -
    # would otherwise be able to blow well past the cap between one
    # check and the next, since `aiter_bytes()` yields already
    # -decompressed chunks).
    async with client.stream("GET", url, headers={"Accept-Encoding": "identity"}) as response:
        status_code = response.status_code
        headers: dict[str, str] = dict(response.headers)
        server_header = response.headers.get("server")
        async for chunk in response.aiter_raw():
            body += chunk
            if len(body) >= MAX_RESPONSE_BYTES:
                break

    # A response that ignored Accept-Encoding and compressed anyway
    # decodes here to mostly-garbage text; that's an acceptable
    # tradeoff (best-effort title extraction just won't find
    # anything), not a bug - the cap above already did its job.
    body_text = body[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")
    title = _extract_title(body_text)

    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    if server_header:
        product, version, extrainfo = _parse_server_header(server_header)

    return HttpProbeResult(
        port=port,
        scheme=scheme,
        status_code=status_code,
        server_header=server_header,
        product=product,
        version=version,
        extrainfo=extrainfo,
        title=title,
        headers=headers,
    )


async def _probe_port(
    client: httpx.AsyncClient,
    host: str,
    port: int,
    semaphore: asyncio.Semaphore,
    timeout_seconds: float,
) -> HttpProbeResult | None:
    """Probe a single port with exactly one scheme attempt.

    Any failure (connection refused, TLS error, timeout, a response that
    can't even be streamed) is caught here and turned into `None` - this
    coroutine never raises for a per-port failure, only genuine misuse
    upstream (e.g. a bad `client`/`host`) would do that.

    `httpx.Timeout(timeout_seconds)` on the client (see
    `_probe_services_async`) only bounds each individual I/O operation
    (connect, one read, one write) - not the request as a whole. A target
    that trickles one byte at a time, each arriving just under the
    per-read timeout, never trips any single per-operation timeout and can
    stall this coroutine indefinitely (worst case: hours), even though
    every individual `await` inside `_probe_port_body` eventually
    "succeeds". `asyncio.wait_for` below adds the missing total-operation
    deadline. `timeout_seconds * 3` (connect + response headers + body
    read, each allowed up to one full per-operation timeout in the worst
    case) is a deliberately generous but still-bounded ceiling - generous
    enough not to cut off a slow-but-legitimate target mid-handshake,
    bounded enough to guarantee `probe_services` returns in a small,
    predictable multiple of its `timeout_seconds` argument no matter how a
    misbehaving target drips bytes.
    """
    async with semaphore:
        try:
            return await asyncio.wait_for(
                _probe_port_body(client, host, port), timeout=timeout_seconds * 3
            )
        except Exception:
            # Covers the full per-port lifecycle - network I/O *and* the
            # post-processing below it (decode/regex/dataclass construction)
            # - plus `asyncio.wait_for`'s own `TimeoutError` when the total
            # deadline above is exceeded, so a future edit to that
            # post-processing can't silently reintroduce a whole-batch
            # failure from one bad target.
            return None


async def _probe_services_async(
    host: str,
    ports: list[int],
    timeout_seconds: float,
    max_concurrency: int,
) -> dict[int, HttpProbeResult]:
    semaphore = asyncio.Semaphore(max_concurrency)
    # verify=False is deliberate, not an oversight: this prober sends no
    # credentials, follows no redirects (follow_redirects=False above), and
    # treats the HTTP response purely as passive fingerprinting evidence -
    # the same posture `nmap -sV`/`curl -k` take. It never authenticates to
    # or trusts the target in any security-relevant way; it just reads a
    # banner. The overwhelmingly common case for this scanner's targets is
    # an internal/lab host with a self-signed or internal-CA certificate on
    # 443/4443/8443 (`_TLS_HEURISTIC_PORTS`); with the default `verify=True`
    # every such probe raises an SSL verification error, gets swallowed by
    # `_probe_port`'s per-port exception handler, and silently omits port
    # 443 - arguably the single most valuable port in the allowlist - from
    # results against exactly the targets this module exists to probe.
    async with httpx.AsyncClient(
        follow_redirects=False, timeout=timeout_seconds, verify=False
    ) as client:
        # `return_exceptions=True` is defense-in-depth, not the primary
        # guard: `_probe_port` already catches everything itself and
        # returns `None` on failure. This just ensures that even if a
        # future edit to `_probe_port` ever let an exception slip through,
        # one bad target still couldn't blow up every other port's result
        # via `asyncio.gather`'s normal fail-fast behavior.
        raw_results = await asyncio.gather(
            *(_probe_port(client, host, port, semaphore, timeout_seconds) for port in ports),
            return_exceptions=True,
        )
    return {result.port: result for result in raw_results if isinstance(result, HttpProbeResult)}


def probe_services(
    host: str,
    ports: Iterable[int],
    timeout_seconds: float = HTTP_PROBE_TIMEOUT_SECONDS,
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
) -> dict[int, HttpProbeResult]:
    """Best-effort HTTP probe of `ports` on `host`; sync wrapper over asyncio.

    Per-port failures (connection refused, TLS error, timeout, malformed
    response) are caught individually inside each port's own coroutine and
    simply omit that port from the returned dict - this function itself
    only raises for genuine misuse (e.g. bad arguments), never because an
    individual probe failed.
    """
    return asyncio.run(_probe_services_async(host, list(ports), timeout_seconds, max_concurrency))
