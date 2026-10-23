"""Common metrics, shared by all components (numpy only, no ML dependencies).

Component-specific metrics (range containment, hierarchical CWE F1, CVSS base-score
error, alert precision/recall) live in each component's own eval code and may use these.
Lead: P4.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Hashable, Iterable, Sequence

import numpy as np


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def prf(tp: int, fp: int, fn: int) -> dict[str, float]:
    p = _safe_div(tp, tp + fp)
    r = _safe_div(tp, tp + fn)
    f = _safe_div(2 * p * r, p + r)
    return {"precision": p, "recall": r, "f1": f}


# ---------------------------------------------------------------- spans (P2)


def span_prf(
    gold: Sequence[Iterable[tuple[int, int, str]]],
    pred: Sequence[Iterable[tuple[int, int, str]]],
    labels: Iterable[str] | None = None,
) -> dict[str, float]:
    """Exact-match span P/R/F1, micro-averaged plus per label.

    gold/pred: one collection of (start, end, label) per document, same order.
    Returns keys like "f1", "precision", "PRODUCT_f1", ...
    """
    if len(gold) != len(pred):
        raise ValueError("gold and pred must have the same number of documents")
    counts: dict[str, Counter] = {}
    for g_doc, p_doc in zip(gold, pred, strict=True):
        g, p = set(g_doc), set(p_doc)
        for span in g | p:
            c = counts.setdefault(span[2], Counter())
            c["tp"] += span in g and span in p
            c["fp"] += span in p and span not in g
            c["fn"] += span in g and span not in p
    wanted = list(labels) if labels is not None else sorted(counts)
    total = Counter()
    out: dict[str, float] = {}
    for label in wanted:
        c = counts.get(label, Counter())
        total.update(c)
        for k, v in prf(c["tp"], c["fp"], c["fn"]).items():
            out[f"{label}_{k}"] = v
    out.update(prf(total["tp"], total["fp"], total["fn"]))
    return out


# ---------------------------------------------------------------- classification (P4)


def accuracy(gold: Sequence[Hashable], pred: Sequence[Hashable]) -> float:
    if len(gold) != len(pred):
        raise ValueError("length mismatch")
    return _safe_div(sum(g == p for g, p in zip(gold, pred, strict=True)), len(gold))


def macro_f1(
    gold: Sequence[Hashable],
    pred: Sequence[Hashable],
    labels: Iterable[Hashable] | None = None,
) -> float:
    """Unweighted mean F1 over `labels` (default: labels that appear in gold)."""
    wanted = list(labels) if labels is not None else sorted(set(gold), key=str)
    scores = []
    for label in wanted:
        tp = sum(g == label and p == label for g, p in zip(gold, pred, strict=True))
        fp = sum(g != label and p == label for g, p in zip(gold, pred, strict=True))
        fn = sum(g == label and p != label for g, p in zip(gold, pred, strict=True))
        scores.append(prf(tp, fp, fn)["f1"])
    return float(np.mean(scores)) if scores else 0.0


def top_k_accuracy(gold: Sequence[Hashable], ranked: Sequence[Sequence[Hashable]], k: int) -> float:
    """Share of items whose gold label is in the first k ranked predictions."""
    hits = sum(g in list(r)[:k] for g, r in zip(gold, ranked, strict=True))
    return _safe_div(hits, len(gold))


def expected_calibration_error(
    confidence: Sequence[float], correct: Sequence[bool], n_bins: int = 15
) -> float:
    """ECE with equal-width bins. confidence = prob of the predicted label."""
    conf = np.asarray(confidence, dtype=float)
    corr = np.asarray(correct, dtype=float)
    if conf.size == 0:
        return 0.0
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    idx = np.clip(np.digitize(conf, bins[1:-1], right=True), 0, n_bins - 1)
    ece = 0.0
    for b in range(n_bins):
        mask = idx == b
        if mask.any():
            ece += mask.mean() * abs(corr[mask].mean() - conf[mask].mean())
    return float(ece)


def mean_absolute_error(gold: Sequence[float], pred: Sequence[float]) -> float:
    g, p = np.asarray(gold, dtype=float), np.asarray(pred, dtype=float)
    return float(np.abs(g - p).mean()) if g.size else 0.0


# ---------------------------------------------------------------- retrieval / linking (P3)


def recall_at_k(
    gold: Sequence[Hashable | None], ranked: Sequence[Sequence[Hashable]], k: int
) -> float:
    """Over non-NIL gold items only: is the gold identifier in the top k candidates?"""
    pairs = [(g, r) for g, r in zip(gold, ranked, strict=True) if g is not None]
    return _safe_div(sum(g in list(r)[:k] for g, r in pairs), len(pairs))


def nil_prf(gold: Sequence[Hashable | None], pred: Sequence[Hashable | None]) -> dict[str, float]:
    """P/R/F1 for predicting NIL (None)."""
    tp = sum(g is None and p is None for g, p in zip(gold, pred, strict=True))
    fp = sum(g is not None and p is None for g, p in zip(gold, pred, strict=True))
    fn = sum(g is None and p is not None for g, p in zip(gold, pred, strict=True))
    return {f"nil_{k}": v for k, v in prf(tp, fp, fn).items()}


# ---------------------------------------------------------------- ranking (P5)


def dcg_at_k(relevances: Sequence[float], k: int) -> float:
    rel = np.asarray(relevances, dtype=float)[:k]
    if rel.size == 0:
        return 0.0
    discounts = np.log2(np.arange(2, rel.size + 2))
    return float(((2**rel - 1) / discounts).sum())


def ndcg_at_k(relevances_in_ranked_order: Sequence[float], k: int) -> float:
    """NDCG@k given the reference relevance of each item, in the order the system ranked them."""
    ideal = dcg_at_k(sorted(relevances_in_ranked_order, reverse=True), k)
    return _safe_div(dcg_at_k(relevances_in_ranked_order, k), ideal)
