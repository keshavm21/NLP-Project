"""Vendor bulletins and security mailing list source (P1).

Manages free-text security advisories without structured fields
(e.g., vendor security advisories, OSS-Security mailing list posts,
Apache/Debian/RedHat security bulletins).
Used for the domain-shift test set (~150 items) per docs/DATA.md.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime, timezone

from vulntriage.ingest.base import Source
from vulntriage.schemas import Advisory
from vulntriage.utils.logging import get_logger

logger = get_logger(__name__)


def _ts(s: str | None) -> datetime | None:
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


class BulletinSource(Source):
    """Source for unstructured vendor bulletins and mailing list posts."""

    name = "bulletin"

    def download(self, force: bool = False) -> None:
        """Verifies or initializes bulletin directory and seed records."""
        out_dir = self.raw_dir
        bulletin_file = out_dir / "bulletins.jsonl"
        if bulletin_file.exists() and not force:
            logger.info("Bulletin: already exists at %s; skipping", bulletin_file)
            return

        # If not present, initialize with starter schema / collection template
        if not bulletin_file.exists():
            bulletin_file.touch()
            logger.info("Bulletin: initialized empty collection at %s", bulletin_file)

    def iter_advisories(self) -> Iterator[Advisory]:
        out_dir = self.raw_dir
        for path in sorted(out_dir.glob("*.jsonl")):
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    adv = _parse_bulletin(record)
                    if adv is not None:
                        yield adv
            except Exception as exc:
                logger.warning("Bulletin: error reading %s: %s", path, exc)


def _parse_bulletin(data: dict) -> Advisory | None:
    b_id = data.get("id", "")
    if not b_id:
        return None

    published = _ts(data.get("published"))
    if published is None:
        return None

    text = data.get("text", "").strip() or data.get("content", "").strip()
    if not text:
        return None

    aliases = [a for a in data.get("aliases", []) if a]
    refs = [r for r in data.get("references", []) if r]

    return Advisory(
        id=b_id,
        aliases=aliases,
        source="bulletin",
        published=published,
        modified=_ts(data.get("modified")),
        title=data.get("title"),
        text=text,
        references=refs,
    )
