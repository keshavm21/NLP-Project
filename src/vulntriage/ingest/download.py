"""Download orchestrator for all P1 sources (P1).

Run via `make data` → `python -m vulntriage.cli data`.

Usage:
    python -m vulntriage.cli data [--force] [--sources nvd,ghsa,...]
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone

from vulntriage.ingest.sources import (
    BulletinSource,
    CPESource,
    CVE5Source,
    CWESource,
    EPSSSource,
    GHSASource,
    KEVSource,
    NVDSource,
    OSVSource,
    VulnrichmentSource,
)
from vulntriage.utils.logging import get_logger

logger = get_logger(__name__)

ALL_SOURCES = {
    "nvd": NVDSource,
    "cve5": CVE5Source,
    "vulnrichment": VulnrichmentSource,
    "ghsa": GHSASource,
    "osv": OSVSource,
    "kev": KEVSource,
    "epss": EPSSSource,
    "cpe": CPESource,
    "cwe": CWESource,
    "bulletin": BulletinSource,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Download all P1 data sources.")
    parser.add_argument(
        "--sources",
        default=",".join(ALL_SOURCES),
        help="Comma-separated list of sources to download (default: all)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download even if files already exist",
    )
    args = parser.parse_args(argv)

    requested = [s.strip() for s in args.sources.split(",") if s.strip()]
    unknown = set(requested) - set(ALL_SOURCES)
    if unknown:
        logger.error("Unknown sources: %s. Available: %s", unknown, list(ALL_SOURCES))
        return 1

    logger.info("Starting download of sources: %s (force=%s)", requested, args.force)
    start = datetime.now(tz=timezone.utc)
    errors: list[str] = []

    for name in requested:
        source = ALL_SOURCES[name]()
        logger.info("=== Downloading %s ===", name)
        try:
            source.download(force=args.force)
        except Exception as exc:
            logger.error("Source %s failed: %s", name, exc, exc_info=True)
            errors.append(f"{name}: {exc}")

    elapsed = (datetime.now(tz=timezone.utc) - start).total_seconds()
    if errors:
        logger.error("Download finished with %d error(s) in %.1fs:", len(errors), elapsed)
        for e in errors:
            logger.error("  %s", e)
        return 1

    logger.info("All downloads complete in %.1fs.", elapsed)
    return 0
