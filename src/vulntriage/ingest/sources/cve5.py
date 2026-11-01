"""CVE JSON 5 (cvelistV5) source (P1).

Clones or updates the CVEProject/cvelistV5 GitHub repo into data/raw/cve5/.
Reads CNA-supplied `affected` blocks with vendor/product/version info,
and CNA CVSS/CWE when available.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from vulntriage.ingest.base import Source
from vulntriage.schemas import Advisory
from vulntriage.utils.logging import get_logger

logger = get_logger(__name__)

_REPO_URL = "https://github.com/CVEProject/cvelistV5.git"
_PLACEHOLDER_CWES = {"NVD-CWE-noinfo", "NVD-CWE-Other"}


def _ts(s: str | None) -> datetime | None:
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


class CVE5Source(Source):
    """Downloads and parses CVE JSON 5 records."""

    name = "cve5"

    def download(self, force: bool = False) -> None:
        out_dir = self.raw_dir
        repo_dir = out_dir / "cvelistV5"
        if repo_dir.exists() and not force:
            logger.info("CVE5: updating existing clone...")
            subprocess.run(["git", "-C", str(repo_dir), "pull", "--ff-only"], check=True)
        else:
            logger.info("CVE5: cloning %s (shallow)...", _REPO_URL)
            # Shallow clone to avoid 2GB history
            subprocess.run(
                ["git", "clone", "--depth=1", _REPO_URL, str(repo_dir)],
                check=True,
            )
        logger.info("CVE5: download complete")

    def iter_advisories(self):
        repo_dir = self.raw_dir / "cvelistV5"
        if not repo_dir.exists():
            logger.warning("CVE5: raw directory not found; run `make data` first")
            return
        for json_path in sorted(repo_dir.rglob("CVE-*.json")):
            adv = _parse_cve5_file(json_path)
            if adv is not None:
                yield adv


def _parse_cve5_file(path: Path) -> Advisory | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.debug("CVE5: skipping %s (%s)", path.name, exc)
        return None

    cve_id = data.get("cveMetadata", {}).get("cveId", "")
    if not cve_id.startswith("CVE-"):
        return None

    published_str = data.get("cveMetadata", {}).get("datePublished")
    published = _ts(published_str)
    if published is None:
        return None

    modified_str = data.get("cveMetadata", {}).get("dateUpdated")
    modified = _ts(modified_str)

    containers = data.get("containers", {})
    cna = containers.get("cna", {})

    # Description (English preferred)
    text = ""
    for desc in cna.get("descriptions", []):
        if desc.get("lang", "").startswith("en"):
            text = desc.get("value", "").strip()
            break
    if not text:
        return None

    aliases: list[str] = []

    # CWE from CNA
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            cwe = desc.get("cweId", "")
            if cwe and cwe not in _PLACEHOLDER_CWES:
                aliases.append(f"cwe:{cwe}")

    refs = [r.get("url", "") for r in cna.get("references", []) if r.get("url")]
    title_obj = cna.get("title")
    title = title_obj if isinstance(title_obj, str) else None

    return Advisory(
        id=cve_id,
        aliases=aliases,
        source="cve5",
        published=published,
        modified=modified,
        title=title,
        text=text,
        references=refs,
    )
