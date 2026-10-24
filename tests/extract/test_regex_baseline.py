from __future__ import annotations

from datetime import datetime

import pytest

from vulntriage.extract.base import Extractor
from vulntriage.extract.regex_baseline import RegexExtractor
from vulntriage.schemas import Advisory


def adv(text: str) -> Advisory:
    return Advisory(id="CVE-2025-0001", source="nvd", published=datetime(2025, 8, 1), text=text)


def affected(text: str, **kwargs) -> list[tuple[str, str | None, str | None]]:
    result = RegexExtractor(**kwargs).extract(adv(text))
    return [(a.product.text, a.vers_range, a.fixed_version) for a in result.affected]


def test_is_an_extractor(advisory):
    ex = RegexExtractor()
    assert isinstance(ex, Extractor)
    result = ex.extract(advisory)
    assert result.advisory_id == advisory.id
    assert result.model == "regex"


def test_conftest_sample(advisory):
    result = RegexExtractor().extract(advisory)
    assert [(s.label, s.text) for s in result.spans] == [
        ("PRODUCT", "libfoo"),
        ("VERSION_EXPR", "before 2.4.3"),
    ]
    (item,) = result.affected
    assert item.vers_range == "vers:generic/<2.4.3"
    assert item.version_spans[0].text == "before 2.4.3"


def test_spans_match_text():
    text = "Apache HTTP Server 2.4.49 and 2.4.50 are affected by a path traversal (CVE-2021-41773)."
    result = RegexExtractor().extract(adv(text))
    for s in result.spans:
        assert text[s.start : s.end] == s.text
    assert affected(text) == [("Apache HTTP Server", "vers:generic/2.4.49|2.4.50", None)]


@pytest.mark.parametrize(
    "text,expected",
    [
        (
            "Django 3.2 before 3.2.19, 4.0 before 4.1.9, and 4.2 before 4.2.1 has a potential "
            "denial of service.",
            [("Django", "vers:generic/>=3.2.0|<3.2.19|>=4.0.0|<4.1.9|>=4.2.0|<4.2.1", None)],
        ),
        (
            "Jenkins Git Plugin 4.11.3 and earlier does not escape the branch name. "
            "This issue is fixed in 4.11.4.",
            [("Jenkins Git Plugin", "vers:generic/<=4.11.3", "4.11.4")],
        ),
        (
            "In urllib3, versions prior to 1.26.5 are affected. "
            "This has been patched in version 1.26.5.",
            [("urllib3", "vers:generic/<1.26.5", "1.26.5")],
        ),
        (
            "Versions before 0.9.5 of lodash-utils are vulnerable to prototype pollution. "
            "Users should upgrade to 0.9.5.",
            [("lodash-utils", "vers:generic/<0.9.5", "0.9.5")],
        ),
        (
            "SomeLib from 1.0.0 to 1.4.2 allows a ReDoS via crafted input.",
            [("SomeLib", "vers:generic/>=1.0.0|<=1.4.2", None)],
        ),
    ],
)
def test_handwritten_advisories(text, expected):
    assert affected(text) == expected


def test_unparseable_range_is_none_not_guessed():
    # "up to" is ambiguous: the span is still extracted, but vers_range stays None.
    result = RegexExtractor().extract(adv("FooBar up to 3.1 is affected."))
    (item,) = result.affected
    assert item.version_spans[0].text == "up to 3.1"
    assert item.vers_range is None


def test_fixed_version_only():
    assert affected("A bug in widgetlib is fixed in 2.0.1.") == []  # no product before a range
    assert affected("widgetlib 1.9.9 crashes. It is fixed in 2.0.1.") == [
        ("widgetlib", "vers:generic/1.9.9", "2.0.1")
    ]


def test_cve_ids_and_years_are_not_versions():
    result = RegexExtractor().extract(adv("CVE-2021-44228 was disclosed in 2021."))
    assert result.spans == []


def test_known_products_take_priority():
    text = "The Apache Log4j 2 library through 2.14.1 allows JNDI lookups."
    assert affected(text, known_products=["Log4j 2"]) == [
        ("Log4j 2", "vers:generic/<=2.14.1", None)
    ]


def test_scheme_is_passed_to_grammar():
    text = "commons-text 1.5 through 1.9 is affected."
    assert affected(text, scheme="maven") == [("commons-text", "vers:maven/>=1.5|<=1.9", None)]
