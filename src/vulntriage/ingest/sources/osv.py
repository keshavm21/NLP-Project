"""OSV (Open Source Vulnerabilities) bulk source (P1).

Downloads per-ecosystem bulk zips from https://osv-vulnerabilities.storage.googleapis.com/.
Restricts to PyPI, npm and Maven ecosystems per docs/DATA.md.
"""

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone

import requests

from vulntriage.ingest.base import Source
from vulntriage.schemas import Advisory
from vulntriage.utils.logging import get_logger

logger = get_logger(__name__)

_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"
_TARGET_ECOSYSTEMS = {"PyPI", "npm", "Maven"}


def _ts(s: str | None) -> datetime | None:
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


class OSVSource(Source):
    """OSV bulk downloads for PyPI, npm, Maven."""

    name = "osv"

    def download(self, force: bool = False) -> None:
        out_dir = self.raw_dir
        for ecosystem in _TARGET_ECOSYSTEMS:
            zip_path = out_dir / f"{ecosystem}.zip"
            if zip_path.exists() and not force:
                logger.info("OSV: %s already downloaded; skipping", ecosystem)
                continue
            url = f"{_BASE_URL}/{ecosystem}/all.zip"
            logger.info("OSV: downloading %s...", url)
            r = requests.get(url, timeout=120, stream=True)
            r.raise_for_status()
            with zip_path.open("wb") as f:
                for chunk in r.iter_content(chunk_size=65536):
                    f.write(chunk)
            logger.info("OSV: %s saved (%d bytes)", ecosystem, zip_path.stat().st_size)

    def iter_advisories(self):
        out_dir = self.raw_dir
        for ecosystem in _TARGET_ECOSYSTEMS:
            zip_path = out_dir / f"{ecosystem}.zip"
            if not zip_path.exists():
                logger.warning("OSV: %s zip not found; run `make data` first", ecosystem)
                continue
            logger.info("OSV: reading %s", zip_path.name)
            with zipfile.ZipFile(zip_path) as zf:
                for name in zf.namelist():
                    if not name.endswith(".json"):
                        continue
                    try:
                        data = json.loads(zf.read(name))
                    except Exception as exc:
                        logger.debug("OSV: skipping %s (%s)", name, exc)
                        continue
                    adv = _parse_osv(data)
                    if adv is not None:
                        yield adv


def _parse_osv(data: dict) -> Advisory | None:
    osv_id = data.get("id", "")
    if not osv_id:
        return None

    published = _ts(data.get("published"))
    if published is None:
        return None

    text = data.get("details", "").strip() or data.get("summary", "").strip()
    if not text:
        return None

    aliases = [a for a in data.get("aliases", []) if a]

    # CWEs from database_specific
    for cwe in data.get("database_specific", {}).get("cwe_ids", []):
        tag = f"cwe:{cwe}"
        if tag not in aliases:
            aliases.append(tag)

    refs = [r.get("url", "") for r in data.get("references", []) if r.get("url")]

    # Add purls for affected packages
    for aff in data.get("affected", []):
        pkg = aff.get("package", {})
        eco = pkg.get("ecosystem", "")
        name = pkg.get("name", "")
        purl = pkg.get("purl", "")
        if purl and purl not in aliases:
            aliases.append(purl)
        elif name and eco in _TARGET_ECOSYSTEMS:
            constructed = f"pkg:{eco.lower()}/{name}"
            if constructed not in aliases:
                aliases.append(constructed)

    # Prefer CVE as canonical ID
    canonical = next((a for a in aliases if a.startswith("CVE-")), osv_id)
    if canonical != osv_id and osv_id not in aliases:
        aliases.append(osv_id)

    return Advisory(
        id=canonical,
        aliases=aliases,
        source="osv",
        published=published,
        modified=_ts(data.get("modified")),
        title=data.get("summary"),
        text=text,
        references=refs,
    )
