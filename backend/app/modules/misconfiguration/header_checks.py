"""Pure HTTP response-header misconfiguration checks (Phase 6).

Zero new network calls -- reads `Service.evidence["headers"]`, already
captured verbatim by Phase 3's `http_prober.py` for every HTTP-probed
(native-scanner) web service. An nmap-scanned HTTPS service has no
`headers` evidence at all (nmap's `-sV` doesn't capture response
headers), so `check_headers` simply produces zero candidates for it --
not an error (see PLAN_6.md section 2).

`evidence["headers"]` is a plain `dict[str, str]` with origin-server
header casing preserved verbatim, never normalized by `http_prober.py` --
every lookup here is case-insensitive via `_get_header`.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from app.modules.misconfiguration.checks import MisconfigCandidate

if TYPE_CHECKING:
    from app.models.service import Service

# Deliberately an independent copy of http_prober.py's private
# `_SERVER_HEADER_RE`, not an import of it -- PLAN_6.md's no-import rule
# for `fingerprinting/` (this module re-derives the same "did the Server
# header parse into product/version" shape locally instead).
_SERVER_HEADER_RE = re.compile(r"^(?P<product>[^\s/]+)/(?P<version>\S+)(?:\s+(?P<extrainfo>.*))?$")


def _get_header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive lookup into a plain dict[str, str] whose keys
    preserve whatever casing the origin server used. Returns None if the
    header isn't present at all.
    """
    lname = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == lname:
            return value
    return None


def check_headers(service: Service) -> list[MisconfigCandidate]:
    """Pure function: reads service.evidence["headers"], returns zero or
    more candidates. Never raises -- a missing/malformed evidence shape
    (evidence is None, not a dict, has no "headers" key, or "headers"
    itself isn't a dict) means "nothing to check", an empty list, not an
    error.
    """
    evidence = service.evidence
    if not isinstance(evidence, dict):
        return []
    headers = evidence.get("headers")
    if not isinstance(headers, dict):
        return []

    scheme = evidence.get("scheme")
    candidates: list[MisconfigCandidate] = []

    if scheme == "https" and _get_header(headers, "Strict-Transport-Security") is None:
        candidates.append(
            MisconfigCandidate(
                check_id="missing-hsts",
                title="Missing Strict-Transport-Security header",
                severity="MEDIUM",
                description=(
                    "This HTTPS service does not send a Strict-Transport-Security "
                    "header, so clients aren't instructed to only connect over "
                    "HTTPS on future visits, leaving room for downgrade/SSL-"
                    "stripping attacks."
                ),
                evidence={"scheme": scheme, "headers": headers},
            )
        )

    if _get_header(headers, "Content-Security-Policy") is None:
        candidates.append(
            MisconfigCandidate(
                check_id="missing-csp",
                title="Missing Content-Security-Policy header",
                severity="LOW",
                description=(
                    "This service does not send a Content-Security-Policy header, "
                    "reducing defense-in-depth against XSS and data-injection "
                    "attacks."
                ),
                evidence={"headers": headers},
            )
        )

    if _get_header(headers, "X-Frame-Options") is None:
        candidates.append(
            MisconfigCandidate(
                check_id="missing-x-frame-options",
                title="Missing X-Frame-Options header",
                severity="LOW",
                description=(
                    "This service does not send an X-Frame-Options header, leaving "
                    "it potentially vulnerable to clickjacking via framing from "
                    "another origin."
                ),
                evidence={"headers": headers},
            )
        )

    x_content_type_options = _get_header(headers, "X-Content-Type-Options")
    if x_content_type_options is None or x_content_type_options.strip().lower() != "nosniff":
        candidates.append(
            MisconfigCandidate(
                check_id="missing-x-content-type-options",
                title="Missing or misconfigured X-Content-Type-Options header",
                severity="LOW",
                description=(
                    "This service does not send 'X-Content-Type-Options: nosniff', "
                    "allowing browsers to MIME-sniff responses and potentially "
                    "execute content as a different content type than declared."
                ),
                evidence={
                    "headers": headers,
                    "x_content_type_options": x_content_type_options,
                },
            )
        )

    server_header = _get_header(headers, "Server")
    if (
        isinstance(server_header, str)
        and server_header.strip()
        and _SERVER_HEADER_RE.match(server_header.strip()) is not None
    ):
        candidates.append(
            MisconfigCandidate(
                check_id="verbose-server-header",
                title="Verbose Server header discloses software/version",
                severity="LOW",
                description=(
                    f"This service's Server header ('{server_header}') discloses "
                    "specific software and version information, which can help an "
                    "attacker target known vulnerabilities for that exact version."
                ),
                evidence={"server": server_header},
            )
        )

    set_cookie = _get_header(headers, "Set-Cookie")
    if isinstance(set_cookie, str):
        # Parse into discrete `;`-separated attributes and compare each
        # trimmed segment against the exact attribute name, rather than a
        # raw substring search across the whole header value - a
        # substring search would false-negative on a cookie whose own
        # name/value happens to contain "secure" or "httponly" (e.g.
        # `secure_session=...`), incorrectly treating the attribute as
        # present when it isn't.
        cookie_attrs = {segment.strip().lower() for segment in set_cookie.split(";")}
        missing_httponly = "httponly" not in cookie_attrs
        missing_secure = scheme == "https" and "secure" not in cookie_attrs
        if missing_httponly or missing_secure:
            if missing_httponly and missing_secure:
                missing_desc = "the HttpOnly and Secure attributes"
            elif missing_httponly:
                missing_desc = "the HttpOnly attribute"
            else:
                missing_desc = "the Secure attribute"
            candidates.append(
                MisconfigCandidate(
                    check_id="insecure-cookie",
                    title="Cookie set without HttpOnly/Secure attribute",
                    severity="MEDIUM",
                    description=(
                        f"This service sets a cookie via Set-Cookie missing "
                        f"{missing_desc}, increasing exposure to XSS-based cookie "
                        "theft and/or transmission over an unencrypted connection."
                    ),
                    evidence={
                        "set_cookie": set_cookie,
                        "missing_httponly": missing_httponly,
                        "missing_secure": missing_secure,
                    },
                )
            )

    return candidates
