"""Tests for the NVD CVE API 2.0 client.

Never makes a real network call: every test constructs an `httpx.Response`
(or exception) in-process and patches `httpx.get` -- the exact call site
`nvd_client.fetch_cves_for_cpe` uses -- to return/raise it. The rate
limiter is replaced with a tiny no-op/raising stub passed in directly as
the `rate_limiter` argument, so these tests never touch real Redis either
(the limiter's own atomicity/concurrency guarantees are covered by
`test_rate_limiter.py` against a real Redis; nothing here needs to
re-prove that).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import httpx
import redis

from app.modules.vulnerability.nvd_client import (
    NVD_BASE_URL,
    NVD_RESULTS_PER_PAGE,
    NormalizedCve,
    fetch_cves_for_cpe,
)
from app.modules.vulnerability.rate_limiter import RateLimiterTimeoutError

CPE23 = "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"


class _NoopRateLimiter:
    """Stub rate limiter: `acquire()` always succeeds immediately."""

    def acquire(self) -> None:
        return None


class _TimeoutRateLimiter:
    """Stub rate limiter: `acquire()` always raises, as the real
    `NvdRateLimiter.acquire()` does once `max_wait_seconds` elapses.
    """

    def acquire(self) -> None:
        raise RateLimiterTimeoutError("timed out waiting for a slot")


class _RedisErrorRateLimiter:
    """Stub rate limiter: `acquire()` raises a Redis-level error, as the
    real `NvdRateLimiter.acquire()` -> `try_acquire()` would if the
    underlying Redis round trip (EVALSHA/EVAL of the rate-limit script)
    itself failed (connection drop, timeout, server restart) rather than
    the rate limiter's own `max_wait_seconds` logic timing out.
    """

    def acquire(self) -> None:
        raise redis.exceptions.ConnectionError("connection refused")


# `redis_client` is never touched by `fetch_cves_for_cpe` whenever a
# `rate_limiter` is explicitly supplied (the internal
# `NvdRateLimiter(redis_client)` construction is skipped), so a bare
# MagicMock stands in for it in every test below -- none of them need
# real Redis.
_FAKE_REDIS = MagicMock(name="redis_client")


def _cve_entry(
    cve_id: str,
    *,
    descriptions: list[dict[str, str]] | None = None,
    metrics: dict[str, Any] | None = None,
    references: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return {
        "cve": {
            "id": cve_id,
            "descriptions": descriptions if descriptions is not None else [],
            "metrics": metrics if metrics is not None else {},
            "references": references if references is not None else [],
        }
    }


_V31_METRICS = {
    "cvssMetricV31": [
        {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/X"}}
    ]
}
_V30_METRICS = {
    "cvssMetricV30": [
        {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.0/X"}}
    ]
}
# Real NVD shape for V2 metrics (confirmed live against the actual NVD
# API, cpe:2.3:a:openbsd:openssh:7.4p1:*:*:*:*:*:*:*, CVE-2007-2768):
# `baseSeverity` is a SIBLING of `cvssData` on the metric object itself,
# NOT nested inside `cvssData` -- CVSS v2.0 doesn't define severity bands
# at all, so NVD computes and attaches `baseSeverity` separately. A
# previous version of this fixture incorrectly nested `baseSeverity`
# inside `cvssData` (matching a bug in the old implementation instead of
# the real API), which masked the bug this fixture now exercises.
_V2_METRICS = {
    "cvssMetricV2": [
        {
            "cvssData": {"baseScore": 5.0, "vectorString": "AV:N/X"},
            "baseSeverity": "MEDIUM",
        }
    ]
}


def test_fetch_cves_normal_response_parses_with_cvss_fallback_priority(monkeypatch) -> None:
    """One CVE per metric tier, plus one CVE that has ALL THREE tiers
    present at once -- proving V31 is preferred over V30/V2 when more
    than one is available, not just "used when it's the only one".
    """
    body = {
        "vulnerabilities": [
            _cve_entry(
                "CVE-2024-0001",
                descriptions=[
                    {"lang": "es", "value": "descripcion"},
                    {"lang": "en", "value": "nginx overflow"},
                ],
                metrics=_V31_METRICS,
                references=[{"url": "http://example.com/1"}, {"url": "http://example.com/2"}],
            ),
            _cve_entry("CVE-2024-0002", metrics=_V30_METRICS),
            _cve_entry(
                "CVE-2024-0003",
                descriptions=[{"lang": "en", "value": "v2 only"}],
                metrics=_V2_METRICS,
                references=[{"url": "http://example.com/3"}],
            ),
            _cve_entry("CVE-2024-0004", metrics={}),  # no metrics at all
            _cve_entry(
                "CVE-2024-0005",
                # All three present: V31 must win.
                metrics={**_V31_METRICS, **_V30_METRICS, **_V2_METRICS},
            ),
        ]
    }
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: httpx.Response(200, json=body))

    result = fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter())

    assert result is not None
    assert result.total_results == len(body["vulnerabilities"])
    assert result.cves == [
        NormalizedCve(
            cve_id="CVE-2024-0001",
            description="nginx overflow",
            severity="CRITICAL",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/X",
            references=["http://example.com/1", "http://example.com/2"],
            raw=body["vulnerabilities"][0]["cve"],
        ),
        NormalizedCve(
            cve_id="CVE-2024-0002",
            description=None,
            severity="HIGH",
            cvss_score=7.5,
            cvss_vector="CVSS:3.0/X",
            references=[],
            raw=body["vulnerabilities"][1]["cve"],
        ),
        NormalizedCve(
            cve_id="CVE-2024-0003",
            description="v2 only",
            severity="MEDIUM",
            cvss_score=5.0,
            cvss_vector="AV:N/X",
            references=["http://example.com/3"],
            raw=body["vulnerabilities"][2]["cve"],
        ),
        NormalizedCve(
            cve_id="CVE-2024-0004",
            description=None,
            severity="NONE",
            cvss_score=None,
            cvss_vector=None,
            references=[],
            raw=body["vulnerabilities"][3]["cve"],
        ),
        NormalizedCve(
            cve_id="CVE-2024-0005",
            description=None,
            severity="CRITICAL",  # V31 wins even though V30/V2 are also present
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/X",
            references=[],
            raw=body["vulnerabilities"][4]["cve"],
        ),
    ]


def test_fetch_cves_v2_only_cve_parses_correct_severity(monkeypatch) -> None:
    """Regression test for the V2 `baseSeverity` location bug: a CPE
    whose ONLY metrics are V2 (the real shape for many pre-~2016 CVEs)
    must parse successfully with the correct severity/score/vector --
    not raise (and get swallowed into a full-lookup-failure `None`) just
    because `baseSeverity` lives beside `cvssData`, not inside it.
    """
    body = {
        "vulnerabilities": [
            _cve_entry(
                "CVE-2007-6750",
                descriptions=[{"lang": "en", "value": "a v2-only CVE"}],
                metrics=_V2_METRICS,
            )
        ]
    }
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: httpx.Response(200, json=body))

    result = fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter())

    assert result is not None
    assert result.cves == [
        NormalizedCve(
            cve_id="CVE-2007-6750",
            description="a v2-only CVE",
            severity="MEDIUM",
            cvss_score=5.0,
            cvss_vector="AV:N/X",
            references=[],
            raw=body["vulnerabilities"][0]["cve"],
        )
    ]


def test_fetch_cves_one_malformed_cve_does_not_blind_the_whole_batch(monkeypatch) -> None:
    """A single CVE with an unexpected/malformed metrics shape (e.g. a
    `cvssMetricV2` entry that isn't a list of dicts) must degrade only
    THAT cve's severity to "NONE"/None/None -- not raise and discard
    every other CVE in the same NVD response for this CPE. This is the
    direct fix for the bug where a V2-only CVE's `KeyError` (from reading
    `baseSeverity` out of the wrong nested location) was caught by a
    broad except that converted the ENTIRE cpe lookup into a `None`.
    """
    body = {
        "vulnerabilities": [
            _cve_entry("CVE-2024-GOOD", metrics=_V31_METRICS),
            {"cve": {"id": "CVE-2024-WEIRD", "metrics": {"cvssMetricV2": "not-a-list"}}},
        ]
    }
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: httpx.Response(200, json=body))

    result = fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter())

    assert result is not None
    assert [cve.cve_id for cve in result.cves] == ["CVE-2024-GOOD", "CVE-2024-WEIRD"]
    weird = result.cves[1]
    assert weird.severity == "NONE"
    assert weird.cvss_score is None
    assert weird.cvss_vector is None


def test_fetch_cves_total_results_from_response_not_len_of_parsed_list(monkeypatch) -> None:
    """`total_results` must reflect NVD's own `totalResults` field, not
    just `len(cves)` -- the whole point of this field (per PLAN_4.md) is
    to let a later audit notice "NVD said there were 40 but we only
    parsed/cached N", which is impossible if this is definitionally
    always equal to the parsed list's length.
    """
    body = {
        "totalResults": 40,
        "vulnerabilities": [_cve_entry("CVE-2024-0001", metrics=_V31_METRICS)],
    }
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: httpx.Response(200, json=body))

    result = fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter())

    assert result is not None
    assert result.total_results == 40
    assert len(result.cves) == 1


def test_fetch_cves_logs_warning_when_response_truncated(monkeypatch, caplog) -> None:
    """When NVD's `totalResults` exceeds `NVD_RESULTS_PER_PAGE`, a warning
    must be logged -- the audit signal the no-pagination scope limit
    depends on an operator being able to grep for.
    """
    body = {
        "totalResults": NVD_RESULTS_PER_PAGE + 1,
        "vulnerabilities": [_cve_entry("CVE-2024-0001", metrics=_V31_METRICS)],
    }
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: httpx.Response(200, json=body))

    with caplog.at_level("WARNING"):
        result = fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter())

    assert result is not None
    assert any("truncated" in record.message for record in caplog.records)


def test_fetch_cves_empty_vulnerabilities_returns_empty_list_not_none(monkeypatch) -> None:
    monkeypatch.setattr(
        httpx, "get", lambda *a, **kw: httpx.Response(200, json={"vulnerabilities": []})
    )

    result = fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter())

    assert result is not None
    assert result.cves == []
    assert result.total_results == 0


def test_fetch_cves_403_returns_none(monkeypatch) -> None:
    monkeypatch.setattr(
        httpx, "get", lambda *a, **kw: httpx.Response(403, json={"message": "forbidden"})
    )

    assert fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter()) is None


def test_fetch_cves_429_returns_none(monkeypatch) -> None:
    monkeypatch.setattr(
        httpx, "get", lambda *a, **kw: httpx.Response(429, json={"message": "too many requests"})
    )

    assert fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter()) is None


def test_fetch_cves_other_non_2xx_status_returns_none(monkeypatch) -> None:
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: httpx.Response(500, json={}))

    assert fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter()) is None


def test_fetch_cves_timeout_exception_returns_none(monkeypatch) -> None:
    def _raise(*args: Any, **kwargs: Any) -> httpx.Response:
        raise httpx.TimeoutException("connect timed out")

    monkeypatch.setattr(httpx, "get", _raise)

    assert fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter()) is None


def test_fetch_cves_connect_error_returns_none(monkeypatch) -> None:
    def _raise(*args: Any, **kwargs: Any) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "get", _raise)

    assert fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter()) is None


def test_fetch_cves_missing_expected_key_returns_none_not_raises(monkeypatch) -> None:
    # No "id" in the cve object -- must be caught, not raised.
    body = {"vulnerabilities": [{"cve": {"descriptions": [], "metrics": {}, "references": []}}]}
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: httpx.Response(200, json=body))

    assert fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter()) is None


def test_fetch_cves_missing_vulnerabilities_key_returns_none(monkeypatch) -> None:
    # Flat/wrong-shaped body entirely -- not nested under "vulnerabilities".
    monkeypatch.setattr(
        httpx, "get", lambda *a, **kw: httpx.Response(200, json=[{"cve": {"id": "CVE-1"}}])
    )

    assert fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter()) is None


def test_fetch_cves_malformed_json_returns_none(monkeypatch) -> None:
    monkeypatch.setattr(
        httpx, "get", lambda *a, **kw: httpx.Response(200, content=b"not json at all")
    )

    assert fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter()) is None


def test_fetch_cves_rate_limiter_timeout_returns_none(monkeypatch) -> None:
    # httpx.get must never even be reached -- the rate limiter gates it.
    monkeypatch.setattr(httpx, "get", MagicMock(side_effect=AssertionError("should not be called")))

    assert fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_TimeoutRateLimiter()) is None


def test_fetch_cves_redis_error_during_rate_limit_acquire_returns_none(monkeypatch) -> None:
    """A Redis-level failure (connection drop, timeout, etc.) while
    acquiring the rate limit slot is distinct from the rate limiter's
    own `RateLimiterTimeoutError` -- both must be swallowed the same
    way, and `httpx.get` must never even be reached.
    """
    monkeypatch.setattr(httpx, "get", MagicMock(side_effect=AssertionError("should not be called")))

    assert fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_RedisErrorRateLimiter()) is None


def test_fetch_cves_no_rate_limiter_constructs_one_from_redis_client(monkeypatch) -> None:
    """When no `rate_limiter` is passed, one is built internally from
    `redis_client` -- this is the "no way to forget" guarantee. Patch the
    class itself so this doesn't touch real Redis.
    """
    import app.modules.vulnerability.nvd_client as nvd_client_module

    fake_limiter = _NoopRateLimiter()
    constructed_with: list[Any] = []

    def _fake_constructor(redis_client: Any) -> _NoopRateLimiter:
        constructed_with.append(redis_client)
        return fake_limiter

    monkeypatch.setattr(nvd_client_module, "NvdRateLimiter", _fake_constructor)
    monkeypatch.setattr(
        httpx, "get", lambda *a, **kw: httpx.Response(200, json={"vulnerabilities": []})
    )

    result = fetch_cves_for_cpe(CPE23, _FAKE_REDIS)

    assert result is not None
    assert result.cves == []
    assert constructed_with == [_FAKE_REDIS]


def test_fetch_cves_apikey_header_present_only_when_configured(monkeypatch) -> None:
    import app.modules.vulnerability.nvd_client as nvd_client_module

    captured_calls: list[dict[str, Any]] = []

    def _capture_get(*args: Any, **kwargs: Any) -> httpx.Response:
        captured_calls.append(kwargs)
        return httpx.Response(200, json={"vulnerabilities": []})

    monkeypatch.setattr(httpx, "get", _capture_get)

    # No API key configured (the phase-4 default): no apiKey header.
    monkeypatch.setattr(nvd_client_module, "get_settings", lambda: MagicMock(NVD_API_KEY=None))
    fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter())
    assert "apiKey" not in captured_calls[-1]["headers"]

    # API key configured: header present with that exact value.
    monkeypatch.setattr(
        nvd_client_module, "get_settings", lambda: MagicMock(NVD_API_KEY="super-secret-key")
    )
    fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter())
    assert captured_calls[-1]["headers"]["apiKey"] == "super-secret-key"


def test_fetch_cves_queries_expected_nvd_url_and_params(monkeypatch) -> None:
    captured_calls: list[tuple[Any, dict[str, Any]]] = []

    def _capture_get(*args: Any, **kwargs: Any) -> httpx.Response:
        captured_calls.append((args, kwargs))
        return httpx.Response(200, json={"vulnerabilities": []})

    monkeypatch.setattr(httpx, "get", _capture_get)

    fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter())

    args, kwargs = captured_calls[-1]
    assert args[0] == NVD_BASE_URL
    # `isVulnerable` must be present with an EMPTY value, not the string
    # "true" -- NVD's real CVE API 2.0 404s on `isVulnerable=true`
    # ("isVulnerable parameter cannot have a value.") and only accepts
    # the bare/empty-valued flag form. This was missed entirely by a
    # dict-equality check alone in an earlier version of this test
    # (both sides agreed on the wrong value), so this assertion is kept
    # deliberately explicit about the exact value, not just the key.
    assert kwargs["params"] == {
        "cpeName": CPE23,
        "isVulnerable": "",
        "resultsPerPage": 200,
    }


def test_fetch_cves_serialized_query_string_matches_nvd_api_requirements(monkeypatch) -> None:
    """Regression test for the `isVulnerable=true` -> 404 bug: asserts
    against the *actual serialized query string* httpx would send on
    the wire (via `httpx.QueryParams`, the same encoder httpx.get uses
    internally), not just the params dict passed in. A dict-level
    assertion alone can't distinguish "this is definitely what hits the
    wire" from "this is what we intended, which might still be wrong in
    a way the dict comparison can't see" -- e.g. a future accidental
    change to `True` (bool) instead of `""` (str) would serialize
    differently (`isVulnerable=true` again) while still being a
    plausible-looking dict value to eyeball.
    """
    captured_params: list[Any] = []

    def _capture_get(*args: Any, **kwargs: Any) -> httpx.Response:
        captured_params.append(kwargs["params"])
        return httpx.Response(200, json={"vulnerabilities": []})

    monkeypatch.setattr(httpx, "get", _capture_get)

    fetch_cves_for_cpe(CPE23, _FAKE_REDIS, rate_limiter=_NoopRateLimiter())

    query_string = str(httpx.QueryParams(captured_params[-1]))
    assert "isVulnerable=&" in query_string or query_string.endswith("isVulnerable=")
    assert "isVulnerable=true" not in query_string
