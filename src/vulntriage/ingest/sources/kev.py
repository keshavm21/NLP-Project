"""CISA Known Exploited Vulnerabilities (KEV) source (P1).

Downloads the KEV JSON feed. KEV does not have advisory text, so
iter_advisories is not implemented; the data is used by benchmark.py
to create exploitation labels.
"""

from __future__ import annotations

import json

import requests

from vulntriage.ingest.base import Source
from vulntriage.utils.logging import get_logger

logger = get_logger(__name__)

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVSource(Source):
    """CISA Known Exploited Vulnerabilities list."""

    name = "kev"

    def download(self, force: bool = False) -> None:
        out_path = self.raw_dir / "known_exploited_vulnerabilities.json"
        if out_path.exists() and not force:
            logger.info("KEV: already downloaded; skipping")
            return
        logger.info("KEV: downloading %s...", _KEV_URL)
        r = requests.get(_KEV_URL, timeout=60)
        r.raise_for_status()
        out_path.write_bytes(r.content)
        logger.info("KEV: saved %d bytes", len(r.content))

    def load_kev_set(self) -> set[str]:
        """Return the set of CVE IDs in KEV."""
        path = self.raw_dir / "known_exploited_vulnerabilities.json"
        if not path.exists():
            logger.warning("KEV: file not found; run `make data` first")
            return set()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            logger.error(
                "KEV: JSON parse error in %s (file may be truncated): %s. "
                "Re-run `make data --force` to re-download.",
                path,
                exc,
            )
            return set()
        return {v["cveID"] for v in data.get("vulnerabilities", []) if v.get("cveID")}

    def load_kev_records(self) -> list[dict]:
        """Return raw KEV vulnerability records."""
        path = self.raw_dir / "known_exploited_vulnerabilities.json"
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            logger.error("KEV: JSON parse error (%s); returning empty list", exc)
            return []
        return data.get("vulnerabilities", [])

    # KEV has no free-text advisory; iter_advisories not implemented
