"""Deduplication of advisories across sources (P1).

Merges records describing the same vulnerability:
1. Shared CVE/GHSA aliases (exact match) — highest confidence.
2. Text similarity fallback for records without shared IDs (bulletins).

The output keeps one Advisory per vulnerability, selecting the best source
(NVD preferred for structured fields) and merging aliases.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from vulntriage.schemas import Advisory
from vulntriage.utils.logging import get_logger

logger = get_logger(__name__)

# Source priority: lower index = preferred when merging
_SOURCE_PRIORITY = ["nvd", "cve5", "vulnrichment", "ghsa", "osv", "bulletin"]

# Similarity threshold for text-based dedup (0–100, rapidfuzz score)
_TEXT_SIM_THRESHOLD = 85


def deduplicate(advisories: Iterable[Advisory]) -> list[Advisory]:
    """Return a deduplicated list; duplicates are merged into one record.

    Algorithm:
    1. Index all advisories by every CVE-xxxx / GHSA-xxx alias.
    2. Union-Find: merge groups that share any alias.
    3. For records with no recognized alias, apply text-similarity within
       the same year bucket (avoids O(n²) over the full corpus).
    4. For each group, pick the best record as primary (source priority)
       and merge all aliases + references.
    """
    all_advs = list(advisories)
    n = len(all_advs)
    logger.info("Dedup: processing %d records", n)

    # --- Build alias index ---
    # alias → list[index into all_advs]
    alias_to_idx: dict[str, list[int]] = defaultdict(list)
    for i, adv in enumerate(all_advs):
        for alias in _iter_ids(adv):
            alias_to_idx[alias].append(i)

    # --- Union-Find ---
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        parent[find(x)] = find(y)

    for indices in alias_to_idx.values():
        for i in range(1, len(indices)):
            union(indices[0], indices[i])

    # --- Text-similarity pass for records without CVE/GHSA IDs ---
    no_id_idx = [
        i
        for i, adv in enumerate(all_advs)
        if not any(a.startswith(("CVE-", "GHSA-")) for a in _iter_ids(adv))
    ]
    if no_id_idx and len(no_id_idx) < 50_000:
        _text_dedup(all_advs, no_id_idx, union)

    # --- Group by root ---
    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(i)

    # --- Merge each group ---
    result: list[Advisory] = []
    for _root, members in groups.items():
        merged = _merge_group([all_advs[i] for i in members])
        result.append(merged)

    duped = n - len(result)
    logger.info("Dedup: %d → %d records (%d duplicates merged)", n, len(result), duped)
    return result


def _iter_ids(adv: Advisory) -> list[str]:
    """All canonical + alias IDs for an advisory (CVE, GHSA only for dedup)."""
    ids = [adv.id]
    for a in adv.aliases:
        if a.startswith(("CVE-", "GHSA-")):
            ids.append(a)
    return ids


def _source_rank(source: str) -> int:
    try:
        return _SOURCE_PRIORITY.index(source)
    except ValueError:
        return len(_SOURCE_PRIORITY)


def _merge_group(group: list[Advisory]) -> Advisory:
    """Merge a group of duplicate advisories into one record."""
    # Sort by source priority; prefer earliest published for tie-breaking
    group = sorted(group, key=lambda a: (_source_rank(a.source), a.published))
    primary = group[0]

    # Merge aliases (deduplicate, preserving order)
    seen_aliases: set[str] = set()
    merged_aliases: list[str] = []
    for adv in group:
        for a in [adv.id, *adv.aliases]:
            if a and a != primary.id and a not in seen_aliases:
                seen_aliases.add(a)
                merged_aliases.append(a)

    # Merge references
    seen_refs: set[str] = set()
    merged_refs: list[str] = []
    for adv in group:
        for r in adv.references:
            if r and r not in seen_refs:
                seen_refs.add(r)
                merged_refs.append(r)

    return primary.model_copy(
        update={
            "aliases": merged_aliases,
            "references": merged_refs,
        }
    )


def _text_dedup(
    all_advs: list[Advisory],
    indices: list[int],
    union_fn,
) -> None:
    """Apply text-similarity dedup within same-year buckets."""
    try:
        from rapidfuzz import fuzz
    except ImportError:
        logger.warning("rapidfuzz not installed; skipping text-similarity dedup")
        return

    # Group by year to reduce comparisons
    by_year: dict[int, list[int]] = defaultdict(list)
    for i in indices:
        by_year[all_advs[i].published.year].append(i)

    merged_count = 0
    for _year, year_indices in by_year.items():
        texts = [all_advs[i].text[:500] for i in year_indices]
        for a in range(len(year_indices)):
            for b in range(a + 1, len(year_indices)):
                score = fuzz.token_sort_ratio(texts[a], texts[b])
                if score >= _TEXT_SIM_THRESHOLD:
                    union_fn(year_indices[a], year_indices[b])
                    merged_count += 1

    if merged_count:
        logger.info("Dedup: text-sim merged %d bulletin pairs", merged_count)
