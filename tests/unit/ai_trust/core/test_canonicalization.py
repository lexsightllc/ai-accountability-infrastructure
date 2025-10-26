import pytest
from datetime import datetime, timezone

from ai_trust.core.canonicalization import canonicalize, CanonicalizationError


def test_canonicalize_floats():
    assert canonicalize(1e6) == "1000000"
    assert canonicalize(1.23e-4) == "0.000123"
    assert canonicalize(42.0) == "42"
    with pytest.raises(CanonicalizationError):
        canonicalize(float("nan"))


def test_canonicalize_datetimes():
    dt = datetime(2023, 5, 1, 12, 30, 0, 123000, tzinfo=timezone.utc)
    assert canonicalize(dt) == '"2023-05-01T12:30:00.123Z"'

    dt_naive = datetime(2023, 5, 1, 12, 30, 0)
    assert canonicalize(dt_naive) == '"2023-05-01T12:30:00Z"'


def test_unicode_normalization():
    # The composed and decomposed forms of "é" should canonicalize identically
    composed = "é"
    decomposed = "e\u0301"
    assert canonicalize(composed) == canonicalize(decomposed)
