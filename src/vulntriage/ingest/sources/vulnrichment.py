"""CISA Vulnrichment source (P1).

Clones or updates cisagov/vulnrichment. Provides ADP-enriched CVSS/CWE/SSVC
for CVEs, particularly covering the NVD backlog period.
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

_REPO_URL = "https://github.com/cisagov/vulnrichment.git"
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


class VulnrichmentSource(Source):
    """CISA Vulnrichment: ADP-enriched labels for CVEs."""

    name = "vulnrichment"

    def download(self, force: bool = False) -> None:
        out_dir = self.raw_dir
        repo_dir = out_dir / "vulnrichment"
        if repo_dir.exists() and not force:
            logger.info("Vulnrichment: updating existing clone...")
            subprocess.run(["git", "-C", str(repo_dir), "pull", "--ff-only"], check=True)
        else:
            logger.info("Vulnrichment: cloning %s (shallow)...", _REPO_URL)
            subprocess.run(
                ["git", "clone", "--depth=1", _REPO_URL, str(repo_dir)],
                check=True,
            )
        logger.info("Vulnrichment: download complete")

    def iter_advisories(self):
        repo_dir = self.raw_dir / "vulnrichment"
        if not repo_dir.exists():
            logger.warning("Vulnrichment: raw directory not found; run `make data` first")
            return
        for json_path in sorted(repo_dir.rglob("CVE-*.json")):
            adv = _parse_vulnrichment(json_path)
            if adv is not None:
                yield adv


def _parse_vulnrichment(path: Path) -> Advisory | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.debug("Vulnrichment: skipping %s (%s)", path.name, exc)
        return None

    cve_id = data.get("cveMetadata", {}).get("cveId", "")
    if not cve_id.startswith("CVE-"):
        return None

    published = _ts(data.get("cveMetadata", {}).get("datePublished"))
    if published is None:
        return None

    modified = _ts(data.get("cveMetadata", {}).get("dateUpdated"))

    # Primary text from CNA
    cna = data.get("containers", {}).get("cna", {})
    text = ""
    for desc in cna.get("descriptions", []):
        if desc.get("lang", "").startswith("en"):
            text = desc.get("value", "").strip()
            break
    if not text:
        return None

    aliases: list[str] = []
    # CWE from CISA ADP container
    for adp in data.get("containers", {}).get("adp", []):
        for pt in adp.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe = desc.get("cweId", "")
                if cwe and cwe not in _PLACEHOLDER_CWES:
                    aliases.append(f"cwe:{cwe}")

    refs = [r.get("url", "") for r in cna.get("references", []) if r.get("url")]

    return Advisory(
        id=cve_id,
        aliases=aliases,
        source="vulnrichment",
        published=published,
        modified=modified,
        text=text,
        references=refs,
    )
