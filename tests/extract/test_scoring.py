from __future__ import annotations

import pytest
from univers.version_range import VersionRange

from vulntriage.extract.scoring import (
    in_scheme,
    item_family,
    match_items,
    probe_versions,
    range_containment,
    range_exact_match,
    score_extraction,
)
from vulntriage.schemas import AffectedItem, ExtractionResult, Span

TEXT = "libfoo before 2.4.3 and libbar 1.x before 1.9 are affected; libfoo is fixed in 2.4.3."


def span(label: str, surface: str, nth: int = 0, text: str = TEXT) -> Span:
    start = -1
    for _ in range(nth + 1):
        start = text.index(surface, start + 1)
    return Span.from_text(text, start, start + len(surface), label)


def item(product: str, version: str | None, vers: str | None, fixed: str | None = None):
    return AffectedItem(
        product=span("PRODUCT", product),
        version_spans=[span("VERSION_EXPR", version)] if version else [],
        vers_range=vers,
        fixed_version=fixed,
    )


GOLD_ITEMS = [
    item("libfoo", "before 2.4.3", "vers:pypi/<2.4.3", "2.4.3"),
    item("libbar", "1.x before 1.9", "vers:pypi/>=1|<1.9"),
]
GOLD = ExtractionResult(
    advisory_id="A1",
    model="gold",
    spans=[
        span("PRODUCT", "libfoo"),
        span("VERSION_EXPR", "before 2.4.3"),
        span("PRODUCT", "libbar"),
        span("VERSION_EXPR", "1.x before 1.9"),
        span("FIXED_VERSION", "2.4.3", nth=1),
    ],
    affected=GOLD_ITEMS,
)


def test_perfect_prediction_scores_one():
    pred = GOLD.model_copy(update={"model": "perfect"})
    scores = score_extraction([GOLD], [pred])["all"]
    for key in (
        "span_f1",
        "item_f1",
        "range_exact_acc",
        "range_containment_acc",
        "fixed_version_acc",
    ):
        assert scores[key] == pytest.approx(1.0), key
    assert scores["n_items"] == 2


def test_generic_prediction_is_read_in_gold_scheme():
    # The extractor doesn't know the ecosystem: "generic" "<2.4.3" must equal gold "pypi" "<2.4.3".
    pred = ExtractionResult(
        advisory_id="A1",
        model="x",
        affected=[
            item("libfoo", "before 2.4.3", "vers:generic/<2.4.3", "2.4.3"),
            item("libbar", "1.x before 1.9", "vers:generic/>=1.0.0|<1.9.0"),
        ],
    )
    scores = score_extraction([GOLD], [pred])["all"]
    assert scores["range_exact_acc"] == 1.0
    assert scores["span_f1"] == 0.0  # no spans predicted


def test_missed_item_counts_against_end_to_end_but_not_matched():
    pred = ExtractionResult(
        advisory_id="A1",
        model="x",
        affected=[item("libfoo", "before 2.4.3", "vers:generic/<=2.4.3")],
    )
    scores = score_extraction([GOLD], [pred])["all"]
    assert scores["item_recall"] == 0.5 and scores["item_precision"] == 1.0
    assert scores["range_exact_acc"] == 0.0
    assert scores["range_exact_acc_matched"] == 0.0  # <= vs <
    assert 0.5 < scores["range_containment_acc_matched"] < 1.0  # disagree only at 2.4.3
    assert scores["range_containment_acc"] == pytest.approx(
        scores["range_containment_acc_matched"] / 2
    )
    assert scores["fixed_version_acc_matched"] == 0.0  # gold 2.4.3, predicted None


def test_missing_prediction_document_is_empty():
    scores = score_extraction([GOLD], [])["all"]
    assert scores["item_recall"] == 0.0 and scores["span_recall"] == 0.0
    assert scores["range_exact_acc"] == 0.0


def test_breakdown_by_family():
    scores = score_extraction([GOLD], [GOLD])
    assert set(scores) == {"all", "phrasing=before", "phrasing=branch_before"}
    assert scores["phrasing=before"]["n_items"] == 1
    assert scores["phrasing=branch_before"]["range_exact_acc"] == 1.0
    for metrics in scores.values():
        assert all(isinstance(v, int | float) for v in metrics.values())  # write_result-ready


def test_none_handling():
    assert range_exact_match(None, None, "generic")  # refusing an ambiguous range is correct
    assert not range_exact_match("vers:generic/<1.0.0", None, "generic")
    assert range_containment(None, None, "generic") == 1.0
    assert range_containment(None, "vers:generic/*", "generic") == 0.0


def test_exact_match_compares_versions_by_value():
    assert range_exact_match("vers:pypi/<1.0", "vers:pypi/<1.0.0", "pypi")
    assert not range_exact_match("vers:pypi/<1.0", "vers:pypi/<=1.0", "pypi")
    assert range_exact_match("vers:npm/*", "vers:generic/*", "npm")


def test_in_scheme():
    assert in_scheme("vers:generic/>=3.0.0|<3.1.1", "maven") == "vers:maven/>=3.0.0|<3.1.1"
    assert in_scheme("vers:maven/<1.1.1t", "pypi") is None  # not a valid pypi version
    assert in_scheme("not a range", "generic") is None


def test_probe_versions_bracket_boundaries():
    probes = probe_versions([VersionRange.from_string("vers:generic/<2.4.3")], "generic")
    assert {"2.4.2", "2.4.3", "2.4.4", "0.0.1", "999999.0.0"} <= set(probes)


def test_matching_by_overlap_when_names_differ():
    text = "Acme WidgetServer before 5.0 allows SSRF."
    gold = AffectedItem(product=span("PRODUCT", "WidgetServer", text=text), vers_range=None)
    pred = AffectedItem(product=span("PRODUCT", "Acme WidgetServer", text=text), vers_range=None)
    assert match_items([gold], [pred]) == [(gold, pred)]


def test_item_family_special_cases():
    assert item_family(item("libfoo", None, None, "2.4.3")) == "fixed_only"
    assert item_family(item("libfoo", None, None)) == "no_version"
    text = "libfoo up to 2.0"
    unparsed = AffectedItem(
        product=span("PRODUCT", "libfoo", text=text),
        version_spans=[span("VERSION_EXPR", "up to 2.0", text=text)],
    )
    assert item_family(unparsed) == "unparsed"
