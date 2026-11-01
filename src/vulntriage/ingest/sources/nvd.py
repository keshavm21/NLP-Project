"""NVD CVE API 2.0 source (P1).

Downloads all CVEs from the NVD REST API (api.nvd.nist.gov/rest/json/cves/2.0).
Rate-limits to 5 req/sec with a key (50/30s without). Idempotent: skips pages
already saved to data/raw/nvd/.

Env:
    NVD_API_KEY  Free key from https://nvd.nist.gov/developers/request-an-api-key
"""

from __future__ import annotations

import json
import math
import time
from datetime import datetime, timezone
from typing import Any

import requests

from vulntriage.config import get_secret
from vulntriage.ingest.base import Source
from vulntriage.schemas import Advisory
from vulntriage.utils.logging import get_logger

logger = get_logger(__name__)

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE_SIZE = 2000
_DELAY_WITH_KEY = 0.6  # 5 req/s
_DELAY_NO_KEY = 6.5  # ~9/min (official limit is 5/30s = 10/min)
_PLACEHOLDER_CWES = {"NVD-CWE-noinfo", "NVD-CWE-Other"}


def _ts(s: str | None) -> datetime | None:
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


class NVDSource(Source):
    """Downloads NVD CVEs via the CVE API 2.0."""

    name = "nvd"

    def download(self, force: bool = False) -> None:
        api_key = get_secret("NVD_API_KEY", required=False)
        delay = _DELAY_WITH_KEY if api_key else _DELAY_NO_KEY
        headers = {"apiKey": api_key} if api_key else {}

        out_dir = self.raw_dir  # auto-created
        meta_path = out_dir / "_meta.json"

        meta: dict[str, Any] = {}
        if meta_path.exists() and not force:
            meta = json.loads(meta_path.read_text())

        logger.info("NVD: fetching total record count...")
        resp = _get(_NVD_API, params={"startIndex": 0, "resultsPerPage": 1}, headers=headers)
        total = resp["totalResults"]
        pages = math.ceil(total / _PAGE_SIZE)
        logger.info("NVD: %d CVEs across %d pages", total, pages)

        downloaded = set(meta.get("pages_done", []))

        for page in range(pages):
            page_path = out_dir / f"page_{page:05d}.json"
            if page_path.exists() and page in downloaded and not force:
                continue
            start = page * _PAGE_SIZE
            time.sleep(delay)
            data = _get(
                _NVD_API,
                params={"startIndex": start, "resultsPerPage": _PAGE_SIZE},
                headers=headers,
            )
            page_path.write_text(json.dumps(data), encoding="utf-8")
            downloaded.add(page)
            meta["pages_done"] = sorted(downloaded)
            meta["total"] = total
            meta["downloaded_at"] = datetime.now(tz=timezone.utc).isoformat()
            meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
            logger.info("NVD: page %d/%d saved", page + 1, pages)

        logger.info("NVD: download complete (%d pages)", pages)

    def iter_advisories(self):
        for page_path in sorted(self.raw_dir.glob("page_*.json")):
            if page_path.stat().st_size == 0:
                continue
            try:
                data = json.loads(page_path.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.warning("NVD: skipping corrupt page %s: %s", page_path.name, exc)
                continue
            for vuln in data.get("vulnerabilities", []):
                adv = _parse_cve(vuln.get("cve", {}))
                if adv is not None:
                    yield adv


def _get(url: str, params: dict, headers: dict, retries: int = 5) -> dict:
    for attempt in range(retries):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=30)
            if r.status_code == 429:
                wait = 30 * (attempt + 1)
                logger.warning("NVD rate-limited; sleeping %ds", wait)
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r.json()
        except requests.RequestException as exc:
            if attempt == retries - 1:
                raise
            logger.warning("NVD request failed (%s); retry %d/%d", exc, attempt + 1, retries)
            time.sleep(5 * (attempt + 1))
    raise RuntimeError("NVD: max retries exceeded")


def _parse_cve(cve: dict) -> Advisory | None:
    """Convert one NVD CVE object to Advisory.  Returns None for invalid records."""
    cve_id = cve.get("id", "")
    if not cve_id.startswith("CVE-"):
        return None

    published = _ts(cve.get("published"))
    if published is None:
        return None

    text = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            text = desc.get("value", "").strip()
            break
    if not text:
        return None

    aliases: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for wd in weakness.get("description", []):
            cwe = wd.get("value", "")
            if cwe and cwe not in _PLACEHOLDER_CWES:
                aliases.append(f"cwe:{cwe}")

    refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

    return Advisory(
        id=cve_id,
        aliases=aliases,
        source="nvd",
        published=published,
        modified=_ts(cve.get("lastModified")),
        text=text,
        references=refs,
    )
