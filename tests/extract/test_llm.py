from __future__ import annotations

import json
from datetime import datetime

from vulntriage.config import load_yaml
from vulntriage.extract.base import Extractor
from vulntriage.extract.llm import (
    LLMExtractor,
    build_messages,
    load_json_output,
    parse_llm_output,
)
from vulntriage.schemas import Advisory

TEXT = (
    "Acme WidgetServer 1.x before 1.9.2 allows SSRF, and libfoo before 2.4.3 allows a heap "
    "overflow. libfoo is fixed in 2.4.3."
)


def reply(*items) -> str:
    return json.dumps({"affected": list(items)})


def item(product, versions=(), vendor=None, fixed=None, **extra):
    return {
        "vendor": vendor,
        "product": product,
        "versions": list(versions),
        "fixed_version": fixed,
        **extra,
    }


def summary(parsed):
    return [
        (a.vendor.text if a.vendor else None, a.product.text, a.vers_range, a.fixed_version)
        for a in parsed.affected
    ]


def test_prompt_file_and_messages():
    prompt = load_yaml("configs/extract/prompts/few_shot.yaml")
    msgs = build_messages("Some advisory.", prompt)
    assert msgs[0]["role"] == "system"
    assert [m["role"] for m in msgs[1:-1]] == ["user", "assistant"] * len(prompt["examples"])
    assert "Some advisory." in msgs[-1]["content"]
    assert len(build_messages("x", prompt, n_examples=0)) == 2  # zero-shot


def test_prompt_examples_follow_their_own_rules():
    # Every string in the hand-written examples must be copied verbatim from the example text.
    prompt = load_yaml("configs/extract/prompts/few_shot.yaml")
    for ex in prompt["examples"]:
        parsed = parse_llm_output(ex["text"], json.dumps(ex["output"]))
        assert parsed.unlocated == [], ex["text"]
        assert all(a.vers_range is not None for a in parsed.affected)


def test_grounded_spans_and_grammar_ranges():
    raw = reply(
        item("WidgetServer", ["1.x before 1.9.2"], vendor="Acme"),
        item("libfoo", ["before 2.4.3"], fixed="2.4.3"),
    )
    parsed = parse_llm_output(TEXT, raw)
    assert summary(parsed) == [
        ("Acme", "WidgetServer", "vers:generic/>=1.0.0|<1.9.2", None),
        (None, "libfoo", "vers:generic/<2.4.3", "2.4.3"),
    ]
    for s in parsed.spans:
        assert TEXT[s.start : s.end] == s.text
    fixed_span = next(s for s in parsed.spans if s.label == "FIXED_VERSION")
    assert fixed_span.start > TEXT.index("fixed in")  # not the "2.4.3" inside "before 2.4.3"


def test_hallucinated_strings_are_dropped():
    raw = reply(item("libfoo", ["before 2.4.3", "before 9.9.9"]), item("ghostlib", ["before 1.0"]))
    parsed = parse_llm_output(TEXT, raw)
    assert [a.product.text for a in parsed.affected] == ["libfoo"]
    assert parsed.affected[0].vers_range is None  # one phrase missing -> no partial range
    assert set(parsed.unlocated) == {"before 9.9.9", "ghostlib"}


def test_case_insensitive_fallback_keeps_text_case():
    parsed = parse_llm_output(TEXT, reply(item("LIBFOO", ["before 2.4.3"])))
    assert parsed.affected[0].product.text == "libfoo"


def test_messy_replies():
    assert load_json_output("Sure!\n```json\n" + reply(item("libfoo")) + "\n```") == [
        item("libfoo")
    ]
    assert load_json_output(json.dumps([item("libfoo")])) == [item("libfoo")]
    assert load_json_output("I cannot help with that.") is None
    assert load_json_output('{"affected": [') is None
    assert parse_llm_output(TEXT, "not json").valid_json is False
    # wrong types are skipped, not fatal
    parsed = parse_llm_output(TEXT, json.dumps({"affected": [{"product": 3}, "x", item("libfoo")]}))
    assert [a.product.text for a in parsed.affected] == ["libfoo"]


def test_llm_vers_ablation():
    raw = reply(
        item("libfoo", ["before 2.4.3"], vers="vers:generic/<2.4.3"),
        item("WidgetServer", ["1.x before 1.9.2"], vers="<1.9.2 please"),
    )
    parsed = parse_llm_output(TEXT, raw, use_llm_vers=True)
    assert [a.vers_range for a in parsed.affected] == ["vers:generic/<2.4.3", None]


def test_extractor_with_fake_backend():
    seen = []

    def generate(messages):
        seen.append(messages)
        return reply(item("libfoo", ["before 2.4.3"], fixed="2.4.3"))

    ex = LLMExtractor(generate, name="fake-llm", n_examples=1)
    assert isinstance(ex, Extractor)
    adv = Advisory(id="CVE-2025-0004", source="nvd", published=datetime(2025, 8, 1), text=TEXT)
    result = ex.extract(adv)
    assert result.model == "fake-llm"
    assert len(seen[0]) == 4  # system + 1 example pair + advisory
    assert [(a.product.text, a.vers_range) for a in result.affected] == [
        ("libfoo", "vers:generic/<2.4.3")
    ]
