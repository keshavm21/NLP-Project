"""Tests for normalization pipeline (P1)."""

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from vulntriage.ingest.normalize import iter_all_advisories
from vulntriage.schemas import Advisory


def test_iter_all_advisories_skips_empty_text():
    adv1 = Advisory(
        id="CVE-2024-001",
        source="nvd",
        published=datetime(2024, 1, 1, tzinfo=timezone.utc),
        text="Valid advisory description.",
    )
    adv2 = Advisory(
        id="CVE-2024-002",
        source="nvd",
        published=datetime(2024, 1, 1, tzinfo=timezone.utc),
        text="   ",  # empty text
    )

    class DummySource:
        name = "dummy"
        raw_dir = Path("/nonexistent")

        def iter_advisories(self):
            yield adv1
            yield adv2

    with patch("vulntriage.ingest.normalize._ADVISORY_SOURCES", [DummySource]):
        with (
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "iterdir", return_value=[Path("f.json")]),
        ):
            results = list(iter_all_advisories())
            assert len(results) == 1
            assert results[0].id == "CVE-2024-001"
