from __future__ import annotations

from datetime import datetime

from vulntriage.extract.grouping import group_affected
from vulntriage.extract.regex_baseline import RegexExtractor
from vulntriage.schemas import Advisory, Span


def spans(text: str, *labeled: tuple[str, str]) -> list[Span]:
    """Build spans from (label, surface) pairs, searching left to right."""
    out, pos = [], 0
    for label, surface in labeled:
        start = text.index(surface, pos)
        out.append(Span.from_text(text, start, start + len(surface), label))
        pos = start + len(surface)
    return out


def summary(items):
    return [(a.product.text, a.vers_range, a.fixed_version) for a in items]


def regex(text: str):
    adv = Advisory(id="X", source="nvd", published=datetime(2025, 8, 1), text=text)
    return summary(RegexExtractor().extract(adv).affected)


# --- multi-product sentences through the regex baseline ----------------------------------------


def test_two_products_two_ranges():
    assert regex("libfoo before 2.4.3 and libbar 1.x before 1.9 allow out-of-bounds reads.") == [
        ("libfoo", "vers:generic/<2.4.3", None),
        ("libbar", "vers:generic/>=1.0.0|<1.9.0", None),
    ]


def test_multiword_products():
    assert regex("Foo Server through 7.4.0 and Bar Client 2.x before 2.3.1 allow CSRF.") == [
        ("Foo Server", "vers:generic/<=7.4.0", None),
        ("Bar Client", "vers:generic/>=2.0.0|<2.3.1", None),
    ]


def test_coordinated_products_share_range():
    assert regex("libfoo, libbaz, and libbar before 1.2.0 mishandle input.") == [
        ("libfoo", "vers:generic/<1.2.0", None),
        ("libbaz", "vers:generic/<1.2.0", None),
        ("libbar", "vers:generic/<1.2.0", None),
    ]


def test_products_in_separate_sentences():
    text = "Foo Server through 7.4.0 allows XSS. Bar Client 2.x before 2.3.1 allows CSRF."
    assert regex(text) == [
        ("Foo Server", "vers:generic/<=7.4.0", None),
        ("Bar Client", "vers:generic/>=2.0.0|<2.3.1", None),
    ]


def test_unattributable_fixed_version_is_not_guessed():
    text = (
        "Foo Server through 7.4.0 allows XSS. Bar Client 2.x before 2.3.1 allows CSRF. "
        "Fixed in 7.4.1."
    )
    assert [f for _, _, f in regex(text)] == [None, None]


def test_fixed_version_in_same_sentence_attaches_left():
    text = "libfoo before 2.4.3 (fixed in 2.4.3) and libbar before 1.9 (fixed in 1.9) are affected."
    assert regex(text) == [
        ("libfoo", "vers:generic/<2.4.3", "2.4.3"),
        ("libbar", "vers:generic/<1.9.0", "1.9"),
    ]


def test_same_product_mentioned_twice_is_merged():
    text = "libfoo before 1.2.0 is affected. libfoo 2.x before 2.3.0 is also affected."
    assert regex(text) == [("libfoo", "vers:generic/<1.2.0|>=2.0.0|<2.3.0", None)]


# --- grouping on hand-built spans (tagger-style output) ---------------------------------------


def test_one_product_two_version_spans():
    text = "libfoo 1.x before 1.9 and 2.x before 2.3 are affected."
    s = spans(
        text,
        ("PRODUCT", "libfoo"),
        ("VERSION_EXPR", "1.x before 1.9"),
        ("VERSION_EXPR", "2.x before 2.3"),
    )
    (item,) = group_affected(text, s)
    assert len(item.version_spans) == 2
    assert item.vers_range == "vers:generic/>=1.0.0|<1.9.0|>=2.0.0|<2.3.0"


def test_version_span_before_product_uses_of():
    text = "Versions prior to 3.0.2 of acme-parser and before 1.1 of acme-cli are affected."
    s = spans(
        text,
        ("VERSION_EXPR", "prior to 3.0.2"),
        ("PRODUCT", "acme-parser"),
        ("VERSION_EXPR", "before 1.1"),
        ("PRODUCT", "acme-cli"),
    )
    # "before 1.1" has acme-parser on its left, but "of acme-cli" is the stronger cue.
    assert summary(group_affected(text, s)) == [
        ("acme-parser", "vers:generic/<3.0.2", None),
        ("acme-cli", "vers:generic/<1.1.0", None),
    ]


def test_vendor_attaches_to_following_product():
    text = "Acme WidgetServer before 5.0 allows SSRF."
    s = spans(text, ("VENDOR", "Acme"), ("PRODUCT", "WidgetServer"), ("VERSION_EXPR", "before 5.0"))
    (item,) = group_affected(text, s)
    assert item.vendor is not None and item.vendor.text == "Acme"
    assert item.vers_range == "vers:generic/<5.0.0"


def test_single_product_fallback_across_sentences():
    text = "A flaw was found in libqux. Versions before 0.8.1 are affected; fixed in 0.8.1."
    s = spans(
        text, ("PRODUCT", "libqux"), ("VERSION_EXPR", "before 0.8.1"), ("FIXED_VERSION", "0.8.1")
    )
    assert summary(group_affected(text, s)) == [("libqux", "vers:generic/<0.8.1", "0.8.1")]


def test_unparseable_span_makes_item_range_none():
    text = "libfoo before 1.2 and libfoo up to 2.0 are affected."
    s = spans(
        text,
        ("PRODUCT", "libfoo"),
        ("VERSION_EXPR", "before 1.2"),
        ("PRODUCT", "libfoo"),
        ("VERSION_EXPR", "up to 2.0"),
    )
    (item,) = group_affected(text, s)
    assert item.vers_range is None
    assert len(item.version_spans) == 2


def test_no_products_no_items():
    text = "Versions before 1.0 are affected."
    assert group_affected(text, spans(text, ("VERSION_EXPR", "before 1.0"))) == []
