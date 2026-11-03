"""Unit tests for `check_headers` (Task 2, PLAN_6.md section 2).

Pure-function module with zero DB/network/Redis dependency -- every test
below builds a plain `types.SimpleNamespace` stand-in carrying only the
`evidence` attribute `check_headers` actually reads, following the same
precedent as `test_confidence.py` (Phase 5) for a pure module with no real
Service/DB dependency.
"""

from __future__ import annotations

import types

from app.modules.misconfiguration.header_checks import check_headers


def _service(evidence: object) -> types.SimpleNamespace:
    return types.SimpleNamespace(evidence=evidence)


def _check_ids(evidence: object) -> set[str]:
    return {c.check_id for c in check_headers(_service(evidence))}


# --- missing-hsts ---


def test_missing_hsts_triggered_for_https_without_header() -> None:
    evidence = {"scheme": "https", "headers": {}}
    candidates = check_headers(_service(evidence))
    matches = [c for c in candidates if c.check_id == "missing-hsts"]
    assert len(matches) == 1
    assert matches[0].severity == "MEDIUM"


def test_missing_hsts_not_triggered_when_header_present() -> None:
    evidence = {
        "scheme": "https",
        "headers": {"Strict-Transport-Security": "max-age=31536000"},
    }
    assert "missing-hsts" not in _check_ids(evidence)


def test_missing_hsts_not_triggered_when_scheme_is_http() -> None:
    evidence = {"scheme": "http", "headers": {}}
    assert "missing-hsts" not in _check_ids(evidence)


def test_missing_hsts_not_triggered_when_scheme_absent() -> None:
    """Edge case (PLAN_6.md section 7): scheme missing entirely (not
    "https", not "http") -- the HSTS check must be correctly skipped, not
    treated as https-by-default.
    """
    evidence = {"headers": {}}
    assert "missing-hsts" not in _check_ids(evidence)


# --- missing-csp ---


def test_missing_csp_triggered_when_header_absent() -> None:
    evidence = {"headers": {}}
    candidates = check_headers(_service(evidence))
    matches = [c for c in candidates if c.check_id == "missing-csp"]
    assert len(matches) == 1
    assert matches[0].severity == "LOW"


def test_missing_csp_not_triggered_when_header_present() -> None:
    evidence = {"headers": {"Content-Security-Policy": "default-src 'self'"}}
    assert "missing-csp" not in _check_ids(evidence)


# --- missing-x-frame-options ---


def test_missing_x_frame_options_triggered_when_header_absent() -> None:
    evidence = {"headers": {}}
    candidates = check_headers(_service(evidence))
    matches = [c for c in candidates if c.check_id == "missing-x-frame-options"]
    assert len(matches) == 1
    assert matches[0].severity == "LOW"


def test_missing_x_frame_options_not_triggered_when_header_present() -> None:
    evidence = {"headers": {"X-Frame-Options": "DENY"}}
    assert "missing-x-frame-options" not in _check_ids(evidence)


# --- missing-x-content-type-options ---


def test_missing_x_content_type_options_triggered_when_header_absent() -> None:
    evidence = {"headers": {}}
    candidates = check_headers(_service(evidence))
    matches = [c for c in candidates if c.check_id == "missing-x-content-type-options"]
    assert len(matches) == 1
    assert matches[0].severity == "LOW"


def test_missing_x_content_type_options_triggered_when_value_is_not_nosniff() -> None:
    evidence = {"headers": {"X-Content-Type-Options": "something-else"}}
    assert "missing-x-content-type-options" in _check_ids(evidence)


def test_missing_x_content_type_options_not_triggered_when_nosniff_case_insensitive() -> None:
    evidence = {"headers": {"X-Content-Type-Options": "NoSniff"}}
    assert "missing-x-content-type-options" not in _check_ids(evidence)


# --- verbose-server-header ---


def test_verbose_server_header_triggered_when_product_version_parses() -> None:
    evidence = {"headers": {"Server": "nginx/1.24.0"}}
    candidates = check_headers(_service(evidence))
    matches = [c for c in candidates if c.check_id == "verbose-server-header"]
    assert len(matches) == 1
    assert matches[0].severity == "LOW"


def test_verbose_server_header_not_triggered_when_unparseable() -> None:
    evidence = {"headers": {"Server": "CustomWebServer"}}
    assert "verbose-server-header" not in _check_ids(evidence)


def test_verbose_server_header_not_triggered_when_absent() -> None:
    evidence = {"headers": {}}
    assert "verbose-server-header" not in _check_ids(evidence)


# --- insecure-cookie ---


def test_insecure_cookie_triggered_when_missing_httponly() -> None:
    evidence = {"headers": {"Set-Cookie": "sessionid=abc; Path=/"}}
    candidates = check_headers(_service(evidence))
    matches = [c for c in candidates if c.check_id == "insecure-cookie"]
    assert len(matches) == 1
    assert matches[0].severity == "MEDIUM"
    assert matches[0].evidence["missing_httponly"] is True


def test_insecure_cookie_triggered_when_https_missing_secure() -> None:
    evidence = {
        "scheme": "https",
        "headers": {"Set-Cookie": "sessionid=abc; HttpOnly"},
    }
    candidates = check_headers(_service(evidence))
    matches = [c for c in candidates if c.check_id == "insecure-cookie"]
    assert len(matches) == 1
    assert matches[0].evidence["missing_httponly"] is False
    assert matches[0].evidence["missing_secure"] is True


def test_insecure_cookie_not_triggered_when_https_and_fully_flagged() -> None:
    evidence = {
        "scheme": "https",
        "headers": {"Set-Cookie": "sessionid=abc; HttpOnly; Secure"},
    }
    assert "insecure-cookie" not in _check_ids(evidence)


def test_insecure_cookie_not_triggered_when_http_and_httponly_present() -> None:
    """Over plain HTTP, Secure isn't required -- only HttpOnly matters."""
    evidence = {
        "scheme": "http",
        "headers": {"Set-Cookie": "sessionid=abc; HttpOnly"},
    }
    assert "insecure-cookie" not in _check_ids(evidence)


def test_insecure_cookie_not_triggered_when_no_set_cookie_header() -> None:
    evidence = {"headers": {}}
    assert "insecure-cookie" not in _check_ids(evidence)


# --- case-insensitive header lookup ---


def test_header_lookup_is_case_insensitive() -> None:
    """Origin-server header casing is preserved verbatim by http_prober.py
    -- a lowercase `strict-transport-security` key must still satisfy the
    missing-hsts check, same as the canonical casing would.
    """
    evidence = {
        "scheme": "https",
        "headers": {"strict-transport-security": "max-age=31536000"},
    }
    assert "missing-hsts" not in _check_ids(evidence)


# --- defensive: malformed/missing evidence shapes never raise ---


def test_evidence_none_returns_empty_list() -> None:
    assert check_headers(_service(None)) == []


def test_evidence_not_a_dict_returns_empty_list() -> None:
    assert check_headers(_service("not-a-dict")) == []


def test_evidence_missing_headers_key_returns_empty_list() -> None:
    assert check_headers(_service({"scheme": "https"})) == []


def test_evidence_with_non_dict_headers_value_returns_empty_list() -> None:
    assert check_headers(_service({"headers": "not-a-dict"})) == []


def test_evidence_empty_dict_returns_empty_list() -> None:
    assert check_headers(_service({})) == []
