"""Normalize raw downloaded data into Advisory objects (P1).

Each source has its own parser (in ingest/sources/). This module
provides a single `iter_all_advisories` function that reads every
installed source and yields normalized Advisory objects.

This is called by benchmark.py; you can also import it directly.
"""

from __future__ import annotations

from collections.abc import Iterator

from vulntriage.ingest.sources import (
    BulletinSource,
    CVE5Source,
    GHSASource,
    NVDSource,
    OSVSource,
    VulnrichmentSource,
)
from vulntriage.schemas import Advisory
from vulntriage.utils.logging import get_logger

logger = get_logger(__name__)

_ALL_SOURCES = [
    GHSASource,
    OSVSource,
    BulletinSource,
    NVDSource,
    CVE5Source,
    VulnrichmentSource,
]

_ADVISORY_SOURCES = [
    GHSASource,
    OSVSource,
    BulletinSource,
]


def iter_all_advisories(sources: list[str] | None = None) -> Iterator[Advisory]:
    """Yield Advisory objects from every source that has downloaded data.

    Args:
        sources: Optional list of source names to include (e.g. ["nvd", "ghsa"]).
                 Defaults to all package advisory sources (GHSA, OSV, Bulletin).
    """
    candidate_sources = _ADVISORY_SOURCES if sources is None else _ALL_SOURCES
    for cls in candidate_sources:
        src = cls()
        if sources is not None and src.name not in sources:
            continue
        raw_dir = src.raw_dir
        if not any(raw_dir.iterdir()) if raw_dir.exists() else True:
            logger.debug("normalize: %s has no raw data; skipping", src.name)
            continue
        logger.info("normalize: reading %s...", src.name)
        count = 0
        skipped = 0
        for adv in src.iter_advisories():
            if not adv.text.strip():
                skipped += 1
                continue
            count += 1
            yield adv
        logger.info(
            "normalize: %s → %d advisories (%d skipped, empty text)", src.name, count, skipped
        )
