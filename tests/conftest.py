"""Shared test fixtures. Tests must never call remote APIs."""

from __future__ import annotations

from datetime import datetime

import pytest

from vulntriage.schemas import Advisory

SAMPLE_TEXT = (
    "A heap overflow in libfoo before 2.4.3 allows remote attackers to execute arbitrary code."
)


@pytest.fixture
def advisory() -> Advisory:
    return Advisory(
        id="CVE-2025-00001",
        aliases=["GHSA-xxxx-yyyy-zzzz"],
        source="nvd",
        published=datetime(2025, 8, 1),
        text=SAMPLE_TEXT,
    )
