"""Extraction scoring (P2): span P/R/F1, range exact-match, range containment, fixed accuracy.

Compares predicted and gold ExtractionResults (matched by advisory_id). Span scores use the
shared span_prf; the rest are scored per gold AffectedItem:

- Items are matched by product name (case/whitespace-insensitive), then by overlapping product
  spans. A gold item with no matching prediction counts as wrong for every range/fixed metric,
  so these are end-to-end numbers; "*_matched" variants score matched items only (isolates
  normalization from detection). Item-level P/R/F1 reports the matching itself.
- Range exact-match: same constraints, versions compared by value in the gold range's scheme
  ("<1.0" equals "<1.0.0" under pypi). Predictions are re-read in the gold scheme (the
  ecosystem isn't in the text, so extractors may use "generic").
  Gold None + predicted None counts as correct: refusing an ambiguous range is the right answer.
- Range containment: on deterministic probe versions around every boundary of either range,
  the fraction where both ranges agree on "affected?" (reproducible instead of random samples).
- Fixed-version accuracy: exact match after stripping a leading "v" (both None = correct).

Breakdown: score_extraction returns {"all": {...}, "phrasing=<family>": {...}, ...}; the family
of a gold item comes from the version grammar applied to its gold version spans. Each entry is
a flat {metric: number} dict ready for eval.results.write_result(subset=...).
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence

from univers.version_range import RANGE_CLASS_BY_SCHEMES, VersionRange

from vulntriage.eval.metrics import prf, span_prf
from vulntriage.extract.version_grammar import parse_version_expr
from vulntriage.schemas import SPAN_LABELS, AffectedItem, ExtractionResult

ItemPair = tuple[AffectedItem, AffectedItem | None]  # (gold, matched prediction or None)


def score_extraction(
    gold: Sequence[ExtractionResult],
    pred: Sequence[ExtractionResult],
    default_scheme: str = "generic",
) -> dict[str, dict[str, float]]:
    """All extraction metrics, overall and per phrasing family of the gold items."""
    pred_by_id = {p.advisory_id: p for p in pred}
    pred_docs = [
        pred_by_id.get(g.advisory_id) or ExtractionResult(advisory_id=g.advisory_id, model="none")
        for g in gold
    ]

    pairs: list[ItemPair] = []
    n_pred_items = 0
    for g, p in zip(gold, pred_docs, strict=True):
        pairs.extend(match_items(g.affected, p.affected))
        n_pred_items += len(p.affected)

    out = {"all": _span_metrics(gold, pred_docs)}
    n_matched = sum(m is not None for _, m in pairs)
    out["all"].update(
        {
            f"item_{k}": v
            for k, v in prf(n_matched, n_pred_items - n_matched, len(pairs) - n_matched).items()
        }
    )
    out["all"].update(_item_metrics(pairs, default_scheme))

    by_family: dict[str, list[ItemPair]] = defaultdict(list)
    for pair in pairs:
        by_family[item_family(pair[0], _scheme_of(pair[0].vers_range, default_scheme))].append(pair)
    for family, fpairs in sorted(by_family.items()):
        out[f"phrasing={family}"] = _item_metrics(fpairs, default_scheme)
    return out


# --- item matching ----------------------------------------------------------------------------


def _key(item: AffectedItem) -> str:
    return " ".join(item.product.text.lower().split())


def match_items(gold: Sequence[AffectedItem], pred: Sequence[AffectedItem]) -> list[ItemPair]:
    """Pair each gold item with at most one prediction: same product name first, then overlap."""
    free = list(pred)
    matched: dict[int, AffectedItem] = {}
    for i, g in enumerate(gold):
        for p in free:
            if _key(p) == _key(g):
                matched[i] = p
                free.remove(p)
                break
    for i, g in enumerate(gold):
        if i in matched:
            continue
        for p in free:
            if p.product.start < g.product.end and g.product.start < p.product.end:
                matched[i] = p
                free.remove(p)
                break
    return [(g, matched.get(i)) for i, g in enumerate(gold)]


# --- metrics ------------------------------------------------------------------------------------


def _span_metrics(gold: Sequence[ExtractionResult], pred: Sequence[ExtractionResult]) -> dict:
    metrics = span_prf(_span_tuples(gold), _span_tuples(pred), labels=SPAN_LABELS)
    return {f"span_{k}": v for k, v in metrics.items()}


def _span_tuples(docs: Sequence[ExtractionResult]) -> list[list[tuple[int, int, str]]]:
    return [[(s.start, s.end, s.label) for s in d.spans] for d in docs]


def _item_metrics(pairs: Sequence[ItemPair], default_scheme: str) -> dict[str, float]:
    exact, contain, fixed = [], [], []
    for g, p in pairs:
        scheme = _scheme_of(g.vers_range, default_scheme)
        if p is None:
            exact.append(None)
            contain.append(None)
            fixed.append(None)
            continue
        exact.append(float(range_exact_match(g.vers_range, p.vers_range, scheme)))
        contain.append(range_containment(g.vers_range, p.vers_range, scheme))
        fixed.append(float(_norm_fixed(g.fixed_version) == _norm_fixed(p.fixed_version)))

    def mean(values, matched_only):
        vals = [v for v in values if v is not None] if matched_only else [v or 0.0 for v in values]
        return sum(vals) / len(vals) if vals else 0.0

    metrics: dict[str, float] = {"n_items": len(pairs)}
    for name, values in (
        ("range_exact", exact),
        ("range_containment", contain),
        ("fixed_version", fixed),
    ):
        metrics[f"{name}_acc"] = mean(values, matched_only=False)
        metrics[f"{name}_acc_matched"] = mean(values, matched_only=True)
    return metrics


def range_exact_match(gold: str | None, pred: str | None, scheme: str) -> bool:
    if gold is None or pred is None:
        return gold is None and pred is None
    g, p = in_scheme(gold, scheme), in_scheme(pred, scheme)
    if g is None or p is None:
        return False
    return _constraints(g) == _constraints(p)


def _constraints(vers: str) -> list[tuple[str, object]]:
    return [(c.comparator, c.version) for c in VersionRange.from_string(vers).constraints]


def range_containment(gold: str | None, pred: str | None, scheme: str) -> float:
    """Share of probe versions on which both ranges agree about being affected."""
    if gold is None or pred is None:
        return float(gold is None and pred is None)
    g, p = in_scheme(gold, scheme), in_scheme(pred, scheme)
    if g is None or p is None:
        return 0.0
    cls = RANGE_CLASS_BY_SCHEMES[scheme]
    g_range, p_range = VersionRange.from_string(g), VersionRange.from_string(p)
    probes = probe_versions([g_range, p_range], scheme)
    agree = sum(
        (cls.version_class(v) in g_range) == (cls.version_class(v) in p_range) for v in probes
    )
    return agree / len(probes)


def in_scheme(vers: str, scheme: str) -> str | None:
    """Re-read a vers: string in another scheme (normalized); None if it doesn't fit there."""
    try:
        rng = VersionRange.from_string(vers)
        if rng.scheme == scheme:
            return str(rng)
        parts = [
            "*"
            if c.comparator == "*"
            else f"{'' if c.comparator == '=' else c.comparator}{c.version.string}"
            for c in rng.constraints
        ]
        return str(VersionRange.from_string(f"vers:{scheme}/" + "|".join(parts)))
    except Exception:  # univers raises various errors for versions invalid in the target scheme
        return None


def probe_versions(ranges: Sequence[VersionRange], scheme: str) -> list[str]:
    """Each boundary version, its numeric neighbours, plus a very low and a very high version."""
    cls = RANGE_CLASS_BY_SCHEMES[scheme]
    candidates = {"0.0.1", "999999.0.0"}
    for rng in ranges:
        for c in rng.constraints:
            if c.comparator == "*":
                continue
            v = c.version.string
            candidates.add(v)
            nums = re.match(r"^(\d+(?:\.\d+)*)", v)
            if nums:
                parts = [int(x) for x in nums.group(1).split(".")]
                for i in range(len(parts)):
                    for delta in (-1, 1):
                        bumped = parts[: i + 1]
                        bumped[i] += delta
                        if bumped[i] >= 0:
                            candidates.add(".".join(map(str, bumped + [0] * (len(parts) - i - 1))))
    valid = []
    for v in sorted(candidates):
        try:
            cls.version_class(v)
            valid.append(v)
        except Exception:  # skip probes the scheme can't represent
            continue
    return valid


def item_family(item: AffectedItem, scheme: str = "generic") -> str:
    """Phrasing family of a gold item, from its version spans."""
    if not item.version_spans:
        return "fixed_only" if item.fixed_version else "no_version"
    if len(item.version_spans) > 1:
        return "multi_span"
    parse = parse_version_expr(item.version_spans[0].text, scheme)
    return parse.family if parse is not None else "unparsed"


def _scheme_of(vers: str | None, default: str) -> str:
    if vers:
        m = re.match(r"^vers:([a-z0-9.+-]+)/", vers)
        if m and m.group(1) in RANGE_CLASS_BY_SCHEMES:
            return m.group(1)
    return default


def _norm_fixed(v: str | None) -> str | None:
    if v is None:
        return None
    v = v.strip()
    return v[1:] if v[:1] in ("v", "V") and v[1:2].isdigit() else v
