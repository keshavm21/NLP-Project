"""Alignment-based silver label generation for extraction (P1).

For each advisory with structured `affected` data (GHSA/OSV ranges,
CVE5 `affected`, NVD CPE configurations), this module:

1. Reads the structured product/version info from the raw source files.
2. Tries to find each product name, vendor, and version boundary in the text
   (exact → case-insensitive → normalized token regex → fuzzy match).
3. Keeps the advisory only if every structured product is found.
4. Produces character-level spans with label + alignment_method.

Output: data/processed/silver/spans.jsonl
"""

from __future__ import annotations

import re
from typing import Any

from vulntriage.schemas import Span, SpanLabel
from vulntriage.utils.logging import get_logger

logger = get_logger(__name__)

try:
    from rapidfuzz import fuzz

    _HAS_RAPIDFUZZ = True
except ImportError:
    _HAS_RAPIDFUZZ = False
    logger.warning("rapidfuzz not installed; fuzzy alignment disabled")

_FUZZY_THRESHOLD = 85  # token_sort_ratio score 0–100


class SilverSpan:
    """One aligned span from silver label generation."""

    __slots__ = (
        "advisory_id",
        "start",
        "end",
        "label",
        "text",
        "alignment_method",
        "structured_value",
    )

    def __init__(
        self,
        advisory_id: str,
        start: int,
        end: int,
        label: str,
        text: str,
        alignment_method: str,
        structured_value: str,
    ) -> None:
        self.advisory_id = advisory_id
        self.start = start
        self.end = end
        self.label = label
        self.text = text
        self.alignment_method = alignment_method
        self.structured_value = structured_value

    def to_dict(self) -> dict[str, Any]:
        return {
            "advisory_id": self.advisory_id,
            "start": self.start,
            "end": self.end,
            "label": self.label,
            "text": self.text,
            "alignment_method": self.alignment_method,
            "structured_value": self.structured_value,
        }

    def to_span(self, full_text: str) -> Span:
        """Convert to validated vulntriage.schemas.Span object."""
        return Span.from_text(full_text, self.start, self.end, self.label)  # type: ignore[arg-type]


def align_advisory(
    advisory_id: str,
    text: str,
    structured_products: list[dict[str, Any]],
) -> list[SilverSpan] | None:
    """Try to align each structured product/version to text.

    `structured_products` is a list of dicts with keys:
        product (str): required product name
        vendor (str, optional): vendor name
        versions (list[str], optional): affected version expressions
        fixed_versions (list[str], optional): fixed versions

    Returns:
        List of SilverSpan if ALL structured products were aligned, else None.
    """
    if not text.strip() or not structured_products:
        return None

    spans: list[SilverSpan] = []
    seen_ranges: set[tuple[int, int]] = set()

    def _add_span(s: SilverSpan | None) -> bool:
        if s is None:
            return False
        # Prevent exact duplicate span ranges
        rng = (s.start, s.end)
        if rng in seen_ranges:
            return False
        seen_ranges.add(rng)
        spans.append(s)
        return True

    for prod_info in structured_products:
        product = (prod_info.get("product") or "").strip()
        vendor = (prod_info.get("vendor") or "").strip()
        versions = prod_info.get("versions") or []
        fixed_versions = prod_info.get("fixed_versions") or []

        if not product:
            continue

        # Try to align product name - MUST be found
        prod_span = _find_in_text(advisory_id, text, product, "PRODUCT")
        if prod_span is None:
            # Cannot find product → drop entire advisory from silver dataset
            return None
        _add_span(prod_span)

        # Optional vendor span
        if vendor:
            vendor_span = _find_in_text(advisory_id, text, vendor, "VENDOR")
            _add_span(vendor_span)

        # Version expressions
        for ver in versions:
            ver_str = str(ver).strip()
            if not ver_str or ver_str == "0":
                continue
            ver_span = _find_in_text(advisory_id, text, ver_str, "VERSION_EXPR")
            _add_span(ver_span)

        # Fixed versions
        for fver in fixed_versions:
            fver_str = str(fver).strip()
            if not fver_str:
                continue
            fver_span = _find_in_text(advisory_id, text, fver_str, "FIXED_VERSION")
            _add_span(fver_span)

    # Sort spans by start offset
    spans.sort(key=lambda s: (s.start, s.end))
    return spans if spans else None


def _find_in_text(
    advisory_id: str,
    text: str,
    target: str,
    label: SpanLabel,
) -> SilverSpan | None:
    """Find `target` in `text` using progressive matching strategies:

    1. Exact match (case-sensitive)
    2. Case-insensitive exact match
    3. Normalized punctuation / token matching
    4. Sliding-window fuzzy token matching (if rapidfuzz available)
    """
    target = target.strip()
    if not target:
        return None

    # 1. Exact match
    idx = text.find(target)
    if idx >= 0:
        return SilverSpan(
            advisory_id=advisory_id,
            start=idx,
            end=idx + len(target),
            label=label,
            text=text[idx : idx + len(target)],
            alignment_method="exact",
            structured_value=target,
        )

    # 2. Case-insensitive exact match
    lower_text = text.lower()
    lower_target = target.lower()
    idx = lower_text.find(lower_target)
    if idx >= 0:
        return SilverSpan(
            advisory_id=advisory_id,
            start=idx,
            end=idx + len(target),
            label=label,
            text=text[idx : idx + len(target)],
            alignment_method="ci_exact",
            structured_value=target,
        )

    # 3. Normalized punctuation / whitespace regex match
    tokens = [t for t in re.split(r"[\s_\.\-]+", target) if t]
    if len(tokens) >= 2:
        pattern = r"\b" + r"[\s_\.\-]+".join(re.escape(t) for t in tokens) + r"\b"
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            start, end = match.span()
            return SilverSpan(
                advisory_id=advisory_id,
                start=start,
                end=end,
                label=label,
                text=text[start:end],
                alignment_method="normalized",
                structured_value=target,
            )

    # 4. Fuzzy match using token spans
    if _HAS_RAPIDFUZZ and len(target) >= 4:
        token_matches = list(re.finditer(r"\S+", text))
        n_toks = len(token_matches)
        target_tok_count = max(1, len(target.split()))
        max_window = min(target_tok_count + 2, 8, n_toks)

        best_score = 0.0
        best_span: tuple[int, int] | None = None

        for w_size in range(max(1, target_tok_count - 1), max_window + 1):
            for i in range(n_toks - w_size + 1):
                start = token_matches[i].start()
                end = token_matches[i + w_size - 1].end()
                candidate = text[start:end]
                # Strip leading/trailing punctuation for scoring
                cand_clean = re.sub(r"^[^\w]+|[^\w]+$", "", candidate)
                if not cand_clean:
                    continue
                score = fuzz.token_sort_ratio(target.lower(), cand_clean.lower())
                if score >= _FUZZY_THRESHOLD and score > best_score:
                    best_score = score
                    # Adjust span to strip trailing punctuation if appropriate
                    m_cand = re.search(re.escape(cand_clean), candidate, re.IGNORECASE)
                    if m_cand:
                        c_start = start + m_cand.start()
                        c_end = start + m_cand.end()
                        best_span = (c_start, c_end)
                    else:
                        best_span = (start, end)

        if best_span is not None:
            b_start, b_end = best_span
            return SilverSpan(
                advisory_id=advisory_id,
                start=b_start,
                end=b_end,
                label=label,
                text=text[b_start:b_end],
                alignment_method=f"fuzzy:{int(best_score)}",
                structured_value=target,
            )

    return None
