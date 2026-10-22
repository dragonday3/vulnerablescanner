"""Tests for the `cve_cache` check/store/staleness module.

Pure DB logic: uses the existing `db` fixture from `conftest.py`, no
Redis/HTTP touched at all.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.models.cve_cache import CveCache
from app.modules.vulnerability.cache import CVE_CACHE_TTL_DAYS, get_cached, is_stale, store
from app.modules.vulnerability.nvd_client import NormalizedCve

CPE23 = "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"


def _make_cves() -> list[NormalizedCve]:
    return [
        NormalizedCve(
            cve_id="CVE-2021-41773",
            description="Path traversal in Apache HTTP Server 2.4.49",
            severity="CRITICAL",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            references=["https://httpd.apache.org/security/vulnerabilities_24.html"],
            raw={"id": "CVE-2021-41773", "sourceIdentifier": "cve@mitre.org", "nested": {"a": 1}},
        ),
        NormalizedCve(
            cve_id="CVE-2021-42013",
            description=None,
            severity="NONE",
            cvss_score=None,
            cvss_vector=None,
            references=[],
            raw={"id": "CVE-2021-42013"},
        ),
    ]


def test_get_cached_returns_none_on_miss(db: Session) -> None:
    assert get_cached(db, "cpe:2.3:a:nonexistent:nonexistent:1.0:*:*:*:*:*:*:*") is None


def test_store_then_get_round_trips_every_field(db: Session) -> None:
    cves = _make_cves()
    stored = store(db, CPE23, cves, total_results=2)

    assert isinstance(stored, CveCache)
    assert stored.cpe == CPE23
    assert stored.total_results == 2

    fetched = get_cached(db, CPE23)
    assert fetched is not None
    assert fetched.cpe == CPE23
    assert fetched.total_results == 2
    assert len(fetched.cves) == 2

    for original, round_tripped in zip(cves, fetched.cves, strict=True):
        assert round_tripped["cve_id"] == original.cve_id
        assert round_tripped["description"] == original.description
        assert round_tripped["severity"] == original.severity
        assert round_tripped["cvss_score"] == original.cvss_score
        assert round_tripped["cvss_vector"] == original.cvss_vector
        assert round_tripped["references"] == original.references
        assert round_tripped["raw"] == original.raw


def test_is_stale_true_past_ttl(db: Session) -> None:
    entry = CveCache(cpe=CPE23, total_results=0, cves=[])
    db.add(entry)
    db.commit()
    db.refresh(entry)

    # Direct DB manipulation, not through store(), since store() sets
    # fetched_at to "now" -- this backdates it past the TTL boundary.
    entry.fetched_at = datetime.now(UTC) - timedelta(days=CVE_CACHE_TTL_DAYS + 1)
    db.commit()
    db.refresh(entry)

    assert is_stale(entry) is True


def test_is_stale_false_for_freshly_stored_row(db: Session) -> None:
    entry = store(db, CPE23, [], total_results=0)
    assert is_stale(entry) is False


def test_store_twice_upserts_instead_of_duplicating(db: Session) -> None:
    first_cves = _make_cves()
    store(db, CPE23, first_cves, total_results=2)

    second_cves = [
        NormalizedCve(
            cve_id="CVE-2022-99999",
            description="A different, later result for the same CPE",
            severity="MEDIUM",
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            references=["https://example.com/advisory"],
            raw={"id": "CVE-2022-99999"},
        )
    ]
    store(db, CPE23, second_cves, total_results=1)

    rows = db.query(CveCache).filter(CveCache.cpe == CPE23).all()
    assert len(rows) == 1

    only_row = rows[0]
    assert only_row.total_results == 1
    assert len(only_row.cves) == 1
    assert only_row.cves[0]["cve_id"] == "CVE-2022-99999"
    assert only_row.cves[0]["severity"] == "MEDIUM"
