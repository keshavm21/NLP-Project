"""NVD CPE API 2.0 source (P1).

Downloads the official CPE Dictionary from the NVD CPE API 2.0
(https://services.nvd.nist.gov/rest/json/cpes/2.0).
Provides candidate names and titles for entity linking (P3).
Rate-limits to 5 req/s with NVD_API_KEY, 6.5s delay without key.
"""

from __future__ import annotations

import json
import math
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any

import requests

from vulntriage.config import get_secret
from vulntriage.ingest.base import Source
from vulntriage.utils.logging import get_logger

logger = get_logger(__name__)

_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
_PAGE_SIZE = 10000
_DELAY_WITH_KEY = 0.6
_DELAY_NO_KEY = 6.5


class CPESource(Source):
    """Downloads NVD CPE Dictionary records via CPE API 2.0."""

    name = "cpe"

    def download(self, force: bool = False, max_pages: int | None = None) -> None:
        api_key = get_secret("NVD_API_KEY", required=False)
        delay = _DELAY_WITH_KEY if api_key else _DELAY_NO_KEY
        headers = {"apiKey": api_key} if api_key else {}

        out_dir = self.raw_dir
        meta_path = out_dir / "_meta.json"

        meta: dict[str, Any] = {}
        if meta_path.exists() and not force:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))

        logger.info("CPE: fetching total count...")
        try:
            resp = _get(_CPE_API, params={"startIndex": 0, "resultsPerPage": 1}, headers=headers)
            total = resp.get("totalResults", 0)
        except Exception as exc:
            logger.error("CPE: count request failed: %s", exc)
            return

        pages = math.ceil(total / _PAGE_SIZE) if total else 0
        if max_pages is not None:
            pages = min(pages, max_pages)
        logger.info("CPE: %d CPEs across %d pages", total, pages)

        downloaded = set(meta.get("pages_done", []))

        for page in range(pages):
            page_path = out_dir / f"page_{page:05d}.json"
            if page_path.exists() and page in downloaded and not force:
                continue
            start = page * _PAGE_SIZE
            time.sleep(delay)
            try:
                data = _get(
                    _CPE_API,
                    params={"startIndex": start, "resultsPerPage": _PAGE_SIZE},
                    headers=headers,
                )
                page_path.write_text(json.dumps(data), encoding="utf-8")
                downloaded.add(page)
                meta["pages_done"] = sorted(downloaded)
                meta["total"] = total
                meta["downloaded_at"] = datetime.now(tz=timezone.utc).isoformat()
                meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
                logger.info("CPE: page %d/%d saved", page + 1, pages)
            except Exception as exc:
                logger.error("CPE: page %d failed: %s", page, exc)
                break

        logger.info("CPE: download completed (%d pages saved)", len(downloaded))

    def iter_cpes(self) -> Iterator[dict[str, Any]]:
        """Yield {cpe_name, title, deprecated} for each CPE in raw storage."""
        for page_path in sorted(self.raw_dir.glob("page_*.json")):
            try:
                data = json.loads(page_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            for item in data.get("products", []):
                cpe_obj = item.get("cpe", {})
                cpe_name = cpe_obj.get("cpeName", "")
                if not cpe_name:
                    continue
                titles = cpe_obj.get("titles", [])
                title = next(
                    (t.get("title") for t in titles if t.get("lang") == "en"),
                    titles[0].get("title") if titles else None,
                )
                yield {
                    "cpe_name": cpe_name,
                    "title": title,
                    "deprecated": cpe_obj.get("deprecated", False),
                }


def _get(url: str, params: dict, headers: dict, retries: int = 3) -> dict:
    for attempt in range(retries):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=30)
            if r.status_code == 429:
                wait = 15 * (attempt + 1)
                logger.warning("CPE rate-limited; sleeping %ds", wait)
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r.json()
        except requests.RequestException as exc:
            if attempt == retries - 1:
                raise
            logger.warning("CPE request failed (%s); retry %d/%d", exc, attempt + 1, retries)
            time.sleep(3 * (attempt + 1))
    raise RuntimeError("CPE: max retries exceeded")
