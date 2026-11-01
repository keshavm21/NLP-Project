"""FIRST EPSS source (P1).

Downloads daily EPSS scores from https://epss.cyentia.com/.
The latest scores file is used; historical data can be fetched by date.
EPSS does not have advisory text; used for ranking features only.
"""

from __future__ import annotations

import csv
import gzip

import requests

from vulntriage.ingest.base import Source
from vulntriage.utils.logging import get_logger

logger = get_logger(__name__)

_EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


class EPSSSource(Source):
    """FIRST EPSS exploitation probability scores."""

    name = "epss"

    def download(self, force: bool = False) -> None:
        out_path = self.raw_dir / "epss_scores-current.csv.gz"
        if out_path.exists() and not force:
            logger.info("EPSS: already downloaded; skipping")
            return
        logger.info("EPSS: downloading %s...", _EPSS_URL)
        r = requests.get(_EPSS_URL, timeout=120)
        r.raise_for_status()
        out_path.write_bytes(r.content)
        logger.info("EPSS: saved %d bytes", len(r.content))

    def load_scores(self) -> dict[str, float]:
        """Return {cve_id: epss_score} mapping from the latest file."""
        path = self.raw_dir / "epss_scores-current.csv.gz"
        if not path.exists():
            logger.warning("EPSS: file not found; run `make data` first")
            return {}
        scores: dict[str, float] = {}
        with gzip.open(path, "rt", encoding="utf-8") as f:
            # Skip header comment line(s) starting with '#'
            reader = csv.reader(line for line in f if not line.startswith("#"))
            header = next(reader, None)
            if header is None:
                return {}
            # Expected: cve,epss,percentile
            cve_col = header.index("cve") if "cve" in header else 0
            epss_col = header.index("epss") if "epss" in header else 1
            for row in reader:
                try:
                    scores[row[cve_col]] = float(row[epss_col])
                except (IndexError, ValueError):
                    continue
        logger.info("EPSS: loaded %d scores", len(scores))
        return scores

    # EPSS has no advisory text; iter_advisories not implemented
