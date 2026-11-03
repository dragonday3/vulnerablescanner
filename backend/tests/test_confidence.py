"""Unit tests for `compute_confidence` (Task 2, PLAN_5.md section 1).

Pure-function module with zero DB/network/Redis dependency -- every test
below builds a plain `types.SimpleNamespace` stand-in carrying only the
`evidence`/`id` attributes `compute_confidence` actually reads, proving no
real `Service` ORM instance (and therefore no DB) is ever required to
exercise this module.
"""

from __future__ import annotations

import types

import pytest

from app.modules.vulnerability import confidence


def _service(method: object, conf: object) -> types.SimpleNamespace:
    """Minimal stand-in for a `Service` row: `compute_confidence` only
    reads `.evidence` (for `method`/`conf`) and `.id` (only when logging
    the unrecognized-method warning), so those are the only two
    attributes this stand-in needs.
    """
    return types.SimpleNamespace(evidence={"method": method, "conf": conf}, id="test-service-id")


@pytest.mark.parametrize(
    ("method", "conf", "expected"),
    [
        # --- worked-examples table, PLAN_5.md section 1 ---
        ("probed", "10", 100.0),
        ("probed", "0", 50.0),
        ("probed", None, 75.0),
        ("table", None, 20.0),
        ("table", "10", 45.0),
        ("table", "0", 0.0),
        (None, None, 10.0),  # method missing entirely
        ("bogus", None, 10.0),  # unrecognized method
        # --- out-of-range / malformed conf, clamped or treated as missing ---
        ("probed", "15", 100.0),  # clamped to 10, same as conf="10"
        ("table", "15", 45.0),  # clamped to 10, same as conf="10"
        ("probed", "-3", 50.0),  # clamped to 0, same as conf="0"
        ("table", "-3", 0.0),  # clamped to 0, same as conf="0"
        ("probed", "abc", 75.0),  # non-numeric -> treated as missing
        ("table", "abc", 20.0),  # non-numeric -> treated as missing
    ],
)
def test_compute_confidence_table(method: object, conf: object, expected: float) -> None:
    assert confidence.compute_confidence(_service(method, conf)) == expected


def test_compute_confidence_never_raises_for_weird_evidence_shapes() -> None:
    """Defensive: a Service with no evidence at all, or a non-dict
    evidence, must still produce a concrete float, never raise.
    """
    assert confidence.compute_confidence(types.SimpleNamespace(evidence=None, id="x")) == 10.0
    assert confidence.compute_confidence(types.SimpleNamespace(evidence={}, id="x")) == 10.0


@pytest.mark.parametrize("conf", range(0, 11))
def test_table_band_never_reaches_probed_band(conf: int) -> None:
    """Band-separation invariant: for every possible conf value 0-10, a
    table-sourced score must be strictly less than a probed-sourced score
    -- proving the structural guarantee holds for the whole range, not
    just the two boundary examples (conf=0, conf=10).
    """
    table_score = confidence.compute_confidence(_service("table", str(conf)))
    probed_score = confidence.compute_confidence(_service("probed", str(conf)))
    assert table_score < probed_score


def test_parse_conf_handles_missing_and_unparseable() -> None:
    assert confidence._parse_conf(None) is None
    assert confidence._parse_conf("abc") is None
    assert confidence._parse_conf("7") == 7
    assert confidence._parse_conf("15") == 10
    assert confidence._parse_conf("-3") == 0
