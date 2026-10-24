from __future__ import annotations

import json
from pathlib import Path

import pytest
from univers.version_range import RANGE_CLASS_BY_SCHEMES, VersionRange

from vulntriage.extract.version_grammar import (
    FAMILIES,
    parse_version_expr,
    render_vers,
    to_vers,
)

FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "version_phrases.json").read_text())
CASES = [
    pytest.param(family, case, id=f"{family}:{case['text']}")
    for family, cases in FIXTURES["families"].items()
    for case in cases
]


def contains(vers: str, version: str) -> bool:
    rng = VersionRange.from_string(vers)
    return RANGE_CLASS_BY_SCHEMES[rng.scheme].version_class(version) in rng


def check(text: str, family: str, vers: str, inside=(), outside=(), scheme: str = "generic"):
    parse = parse_version_expr(text, scheme)
    assert parse is not None, text
    assert parse.family == family
    assert parse.vers == vers
    for v in inside:
        assert contains(parse.vers, v), f"{v} should be in {parse.vers}"
    for v in outside:
        assert not contains(parse.vers, v), f"{v} should not be in {parse.vers}"
    return parse


# --- one test per family ----------------------------------------------------------------------


def test_before():
    check("before 2.4.3", "before", "vers:generic/<2.4.3", ["2.4.2"], ["2.4.3"])


def test_prior_to():
    check("prior to 2.4.3", "prior_to", "vers:generic/<2.4.3", ["2.4.2"], ["2.4.3"])


def test_through():
    check("through 2.4.3", "through", "vers:generic/<=2.4.3", ["2.4.3"], ["2.4.4"])


def test_up_to_and_including():
    check("up to and including 2.4.3", "up_to_including", "vers:generic/<=2.4.3", ["2.4.3"])


def test_up_to_excluding():
    check("up to (excluding) 2.4.3", "up_to_excluding", "vers:generic/<2.4.3", [], ["2.4.3"])


def test_and_earlier():
    check("2.4.3 and earlier", "and_earlier", "vers:generic/<=2.4.3", ["2.4.3"], ["2.4.4"])


def test_and_later():
    check("2.0 and later", "and_later", "vers:generic/>=2.0.0", ["2.0.0"], ["1.9.9"])


def test_x_before_y():
    check(
        "3.x before 3.1.1",
        "branch_before",
        "vers:generic/>=3.0.0|<3.1.1",
        ["3.1.0"],
        ["2.9", "3.1.1"],
    )


def test_from_a_to_b_is_inclusive():
    check("from 1.0 to 1.5", "from_to", "vers:generic/>=1.0.0|<=1.5.0", ["1.5.0"], ["1.5.1"])


def test_a_through_b():
    check("1.0 through 1.5", "a_through_b", "vers:generic/>=1.0.0|<=1.5.0", ["1.0.0"], ["0.9"])


def test_operator():
    check(">= 1.0, < 2.0", "operator", "vers:generic/>=1.0.0|<2.0.0", ["1.9"], ["2.0"])


def test_series():
    check("2.x", "series", "vers:generic/>=2.0.0|<3.0.0", ["2.5"], ["3.0"])


def test_single():
    check("2.4.3", "single", "vers:generic/2.4.3", ["2.4.3"], ["2.4.2"])


def test_list_two():
    check("2.4.3 and 3.1.1", "list", "vers:generic/2.4.3|3.1.1", ["2.4.3", "3.1.1"], ["3.0"])


def test_list_oxford():
    check("1.0, 1.1 and 1.2", "list", "vers:generic/1.0.0|1.1.0|1.2.0")


def test_multi_range():
    check(
        "before 1.2.3, 2.x before 2.4.5, and 3.x before 3.1.1",
        "multi_range",
        "vers:generic/<1.2.3|>=2.0.0|<2.4.5|>=3.0.0|<3.1.1",
        ["1.2.2", "2.4.4", "3.1.0"],
        ["1.2.3", "2.4.5", "3.1.1"],
    )


def test_fixed_in():
    parse = check("fixed in 2.4.3", "fixed_in", "vers:generic/<2.4.3", ["2.4.2"], ["2.4.3"])
    assert parse.fixed_versions == ("2.4.3",)


def test_all_versions():
    check("all versions", "all_versions", "vers:generic/*", ["0.0.1", "99.0.0"])


def test_every_family_has_a_fixture():
    assert set(FIXTURES["families"]) == set(FAMILIES)


# --- fixtures ---------------------------------------------------------------------------------


@pytest.mark.parametrize("family,case", CASES)
def test_fixture_phrasings(family, case):
    parse = check(
        case["text"],
        family,
        case["vers"],
        case["in"],
        case["out"],
        case.get("scheme", "generic"),
    )
    assert list(parse.fixed_versions) == case.get("fixed", [])


@pytest.mark.parametrize("case", FIXTURES["unparseable"], ids=lambda c: c["text"] or "<empty>")
def test_unparseable_returns_none(case):
    assert parse_version_expr(case["text"]) is None
    assert to_vers(case["text"]) is None


# --- schemes and details ------------------------------------------------------------------------


def test_scheme_decides_validity():
    # Four-part and letter-suffixed versions are fine for maven but not for semver schemes.
    assert to_vers("1.2.3.4 and earlier", "maven") == "vers:maven/<=1.2.3.4"
    assert to_vers("before 1.1.1t", "maven") == "vers:maven/<1.1.1t"
    assert to_vers("1.2.3.4 and earlier", "npm") is None
    assert to_vers("2.x", "pypi") == "vers:pypi/>=2|<3"


def test_pypi_normalizes_prerelease():
    assert to_vers("before 2.4.3-RC1", "pypi") == "vers:pypi/<2.4.3rc1"


def test_maven_qualifier_case_is_kept():
    assert to_vers("1.0 to 2.0.RELEASE", "maven") == "vers:maven/>=1.0|<=2.0.RELEASE"


def test_unknown_scheme_raises():
    with pytest.raises(ValueError):
        parse_version_expr("before 1.0", "not-a-scheme")


def test_overlapping_ranges_are_merged():
    parse = parse_version_expr("before 2.0 and 1.x before 1.5")
    assert parse is not None and parse.vers == "vers:generic/<2.0.0"
    parse = parse_version_expr("1.0 through 1.5 and 1.5 through 2.0")
    assert parse is not None and parse.vers == "vers:generic/>=1.0.0|<=2.0.0"


def test_list_with_duplicate_collapses():
    assert to_vers("1.0.1, 1.0.1 and 1.0.2") == "vers:generic/1.0.1|1.0.2"


def test_render_and_contains_agree():
    parse = parse_version_expr("3.x before 3.1.1")
    assert parse is not None
    assert render_vers(parse) == parse.vers
    assert parse.contains("3.0.5") and not parse.contains("3.1.1")


def test_output_round_trips_through_univers():
    for _, case in (p.values for p in CASES):
        vers = to_vers(case["text"], case.get("scheme", "generic"))
        assert str(VersionRange.from_string(vers)) == vers
