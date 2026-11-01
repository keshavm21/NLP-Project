"""GitHub Advisory Database (GHSA) source (P1).

Clones github/advisory-database. Advisories are in OSV format.
Restricts to PyPI, npm and Maven ecosystems per docs/DATA.md.
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

_REPO_URL = "https://github.com/github/advisory-database.git"
# Per DATA.md, focus on these three ecosystems
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


class GHSASource(Source):
    """GitHub Advisory Database (reviewed advisories only)."""

    name = "ghsa"

    def download(self, force: bool = False) -> None:
        out_dir = self.raw_dir
        repo_dir = out_dir / "advisory-database"
        if repo_dir.exists() and not force:
            logger.info("GHSA: updating existing clone...")
            subprocess.run(["git", "-C", str(repo_dir), "pull", "--ff-only"], check=True)
        else:
            logger.info("GHSA: cloning %s (shallow)...", _REPO_URL)
            subprocess.run(
                ["git", "clone", "--depth=1", _REPO_URL, str(repo_dir)],
                check=True,
            )
        logger.info("GHSA: download complete")

    def iter_advisories(self):
        repo_dir = self.raw_dir / "advisory-database"
        reviewed = repo_dir / "advisories" / "github-reviewed"
        if not reviewed.exists():
            logger.warning("GHSA: reviewed directory not found; run `make data` first")
            return
        for json_path in sorted(reviewed.rglob("*.json")):
            adv = _parse_ghsa(json_path)
            if adv is not None:
                yield adv


def _parse_ghsa(path: Path) -> Advisory | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.debug("GHSA: skipping %s (%s)", path.name, exc)
        return None

    ghsa_id = data.get("id", "")
    if not ghsa_id.startswith("GHSA-"):
        return None

    published = _ts(data.get("published"))
    if published is None:
        return None

    # Only include if at least one affected package is in our target ecosystems
    affected = data.get("affected", [])
    ecosystems = {a.get("package", {}).get("ecosystem", "") for a in affected}
    if not ecosystems.intersection(_TARGET_ECOSYSTEMS):
        return None

    text = data.get("details", "").strip() or data.get("summary", "").strip()
    if not text:
        return None

    # Collect aliases (CVE IDs etc.)
    aliases = [a for a in data.get("aliases", []) if a]

    # CWE IDs
    for db in data.get("database_specific", {}).get("cwe_ids", []):
        if db and f"cwe:{db}" not in aliases:
            aliases.append(f"cwe:{db}")

    refs = [r.get("url", "") for r in data.get("references", []) if r.get("url")]

    # Add purls for affected packages
    for aff in affected:
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

    # Use CVE as canonical ID if available, otherwise GHSA
    canonical = next((a for a in aliases if a.startswith("CVE-")), ghsa_id)
    # Keep GHSA in aliases if CVE is canonical
    if canonical != ghsa_id and ghsa_id not in aliases:
        aliases.append(ghsa_id)

    return Advisory(
        id=canonical,
        aliases=aliases,
        source="ghsa",
        published=published,
        modified=_ts(data.get("modified")),
        title=data.get("summary"),
        text=text,
        references=refs,
    )
