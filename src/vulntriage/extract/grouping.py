"""Rule-based grouping: attach VERSION_EXPR / FIXED_VERSION / VENDOR spans to PRODUCT spans.

Independent of how the spans were found, so the regex baseline and the tagger share it.

Rules, applied per version span (all within one sentence):
  0. "<range> of <product>" attaches to that product ("before 1.1 of acme-cli").
  1. Otherwise attach to the nearest PRODUCT on the left
     ("libfoo before 2.4.3 and libbar 1.x before 1.9").
  2. Products coordinated with it share the range ("libfoo and libbar before 1.2").
  3. No product on the left: attach to a product right after "of/in/for"
     ("versions before 2.4.3 of libfoo").
  4. Still nothing: if the advisory names exactly one product, attach to it.
FIXED_VERSION spans use rules 1 and 4 only. A VENDOR directly before a product attaches to it.
Mentions of the same product (case-insensitive) become one AffectedItem with the ranges unioned;
if any of its version spans can't be parsed, vers_range is None.
"""

from __future__ import annotations

import re

from vulntriage.extract.version_grammar import combine, parse_version_expr
from vulntriage.schemas import AffectedItem, Span

_SENTENCE_END = re.compile(r"[.!?](?=\s+[A-Z(])|\n\s*\n")
_COORD_GAP = re.compile(r"^\s*(?:,\s*(?:and|or)?|and|or|&|/)\s*$", re.I)
_RIGHT_GAP = re.compile(r"^\s*(?:of|in|for)\s+(?:the\s+)?$", re.I)
_OF_GAP = re.compile(r"^\s*of\s+(?:the\s+)?$", re.I)
_VENDOR_GAP = re.compile(r"^\s{0,2}$")


def sentence_ids(text: str) -> list[int]:
    """Sentence index for every character offset in `text`."""
    ids = [0] * (len(text) + 1)
    sid, start = 0, 0
    for m in _SENTENCE_END.finditer(text):
        for i in range(start, m.end()):
            ids[i] = sid
        sid, start = sid + 1, m.end()
    for i in range(start, len(text) + 1):
        ids[i] = sid
    return ids


def group_affected(
    text: str,
    spans: list[Span],
    scheme: str = "generic",
) -> list[AffectedItem]:
    """Build AffectedItems from labeled spans over `text`, in order of first product mention."""
    sent = sentence_ids(text)
    products = sorted((s for s in spans if s.label == "PRODUCT"), key=lambda s: s.start)
    if not products:
        return []
    by_key: dict[str, list[Span]] = {}
    for p in products:
        by_key.setdefault(_key(p), []).append(p)
    single = by_key[_key(products[0])] if len(by_key) == 1 else None

    versions: dict[str, list[Span]] = {k: [] for k in by_key}
    fixed: dict[str, list[Span]] = {k: [] for k in by_key}
    for s in sorted(spans, key=lambda s: s.start):
        if s.label not in ("VERSION_EXPR", "FIXED_VERSION"):
            continue
        targets = _targets(text, s, products, sent, allow_right=s.label == "VERSION_EXPR")
        if not targets and single is not None:
            targets = [single[0]]
        out = versions if s.label == "VERSION_EXPR" else fixed
        for key in dict.fromkeys(_key(t) for t in targets):
            out[key].append(s)

    vendors = [s for s in spans if s.label == "VENDOR"]
    items = []
    for key, mentions in by_key.items():
        vspans, fspans = versions[key], fixed[key]
        fixed_values = list(dict.fromkeys(f.text.strip() for f in fspans))
        fixed_version = fixed_values[0] if len(fixed_values) == 1 else None
        items.append(
            AffectedItem(
                vendor=_vendor_for(text, mentions, vendors),
                product=mentions[0],
                version_spans=vspans,
                vers_range=_range(vspans, fixed_version, scheme),
                fixed_version=fixed_version,
            )
        )
    return items


def _key(span: Span) -> str:
    return " ".join(span.text.lower().split())


def _targets(
    text: str, span: Span, products: list[Span], sent: list[int], allow_right: bool
) -> list[Span]:
    same = [p for p in products if sent[p.start] == sent[span.start]]
    if allow_right:  # rule 0: an explicit "<range> of <product>" beats proximity
        for p in same:
            if p.start >= span.end and _OF_GAP.match(text[span.end : p.start]):
                return [p]
    left = [p for p in same if p.end <= span.start]
    if left:
        group = [left[-1]]
        for p in reversed(left[:-1]):  # rule 2: walk left over "X, Y and Z"
            if not _COORD_GAP.match(text[p.end : group[-1].start]):
                break
            group.append(p)
        return group
    if allow_right:
        for p in same:
            if p.start >= span.end and _RIGHT_GAP.match(text[span.end : p.start]):
                return [p]
    return []


def _vendor_for(text: str, mentions: list[Span], vendors: list[Span]) -> Span | None:
    for p in mentions:
        for v in vendors:
            if v.end <= p.start and _VENDOR_GAP.match(text[v.end : p.start]):
                return v
    return None


def _range(vspans: list[Span], fixed_version: str | None, scheme: str) -> str | None:
    if vspans:
        parse = combine([parse_version_expr(v.text, scheme) for v in vspans])
    elif fixed_version is not None:
        parse = parse_version_expr(f"fixed in {fixed_version}", scheme)
    else:
        return None
    return None if parse is None else parse.vers
