from __future__ import annotations

import re
import subprocess
import sys
from datetime import datetime

import pytest

from vulntriage.config import get_paths, load_yaml
from vulntriage.extract.tagger import (
    BIO_LABELS,
    ID2LABEL,
    IGNORE_INDEX,
    LABEL2ID,
    DebertaTagger,
    spans_to_token_labels,
    token_labels_to_spans,
)
from vulntriage.schemas import Advisory, Span


class StubTokenizer:
    """Fast-tokenizer stand-in: words and punctuation, split into 3-char "subwords".

    With leading_space=True the first subword of a word starts at the preceding space, like
    SentencePiece's "▁word" pieces. Adds (0, 0) special tokens at both ends.
    """

    def __init__(self, leading_space: bool = False) -> None:
        self.leading_space = leading_space

    def __call__(self, text, return_offsets_mapping=True, truncation=True, max_length=512):
        offsets = [(0, 0)]
        for m in re.finditer(r"\w+|[^\w\s]", text):
            for i in range(m.start(), m.end(), 3):
                start = i
                if i == m.start() and self.leading_space and i > 0 and text[i - 1] == " ":
                    start = i - 1
                offsets.append((start, min(i + 3, m.end())))
        offsets = offsets[: max_length - 1] + [(0, 0)]
        return {"input_ids": list(range(len(offsets))), "offset_mapping": offsets}


TEXT = "libfoo before 2.4.3 (fixed in 2.4.3) and Acme WidgetServer 1.x before 1.9 are affected."


def gold_spans(text: str = TEXT) -> list[Span]:
    out, pos = [], 0
    for label, surface in [
        ("PRODUCT", "libfoo"),
        ("VERSION_EXPR", "before 2.4.3"),
        ("FIXED_VERSION", "2.4.3"),
        ("VENDOR", "Acme"),
        ("PRODUCT", "WidgetServer"),
        ("VERSION_EXPR", "1.x before 1.9"),
    ]:
        start = text.index(surface, pos)
        out.append(Span.from_text(text, start, start + len(surface), label))
        pos = start + len(surface)
    return out


def tags(label_ids):
    return [ID2LABEL.get(i, "-") for i in label_ids]


def test_label_maps():
    assert BIO_LABELS[0] == "O"
    assert len(BIO_LABELS) == 9
    assert all(ID2LABEL[LABEL2ID[lab]] == lab for lab in BIO_LABELS)
    assert "B-VERSION_EXPR" in LABEL2ID and "I-FIXED_VERSION" in LABEL2ID


def test_config_labels_match_code():
    cfg = load_yaml(get_paths().configs / "extract" / "deberta_tagger.yaml")
    assert tuple(cfg["labels"]) == BIO_LABELS
    assert cfg["model"]["name"] == "microsoft/deberta-v3-base"
    assert len(cfg["training"]["seeds"]) == 3


def test_spans_to_token_labels_simple():
    text = "libfoo before 2.4.3"
    enc = StubTokenizer()(text)
    span_p = Span.from_text(text, 0, 6, "PRODUCT")
    span_v = Span.from_text(text, 7, 19, "VERSION_EXPR")
    labels = spans_to_token_labels(text, enc["offset_mapping"], [span_p, span_v])
    # [CLS] lib foo bef ore 2 . 4 . 3 [SEP]
    assert tags(labels) == [
        "-", "B-PRODUCT", "I-PRODUCT", "B-VERSION_EXPR", "I-VERSION_EXPR", "I-VERSION_EXPR",
        "I-VERSION_EXPR", "I-VERSION_EXPR", "I-VERSION_EXPR", "I-VERSION_EXPR", "-",
    ]  # fmt: skip
    assert labels[0] == labels[-1] == IGNORE_INDEX


def test_leading_space_offsets_do_not_leak_into_previous_span():
    text = "libfoo before 2.4.3"
    enc = StubTokenizer(leading_space=True)(text)
    assert enc["offset_mapping"][3] == (6, 10)  # " bef"
    labels = spans_to_token_labels(
        text, enc["offset_mapping"], [Span.from_text(text, 0, 6, "PRODUCT")]
    )
    assert tags(labels)[1:4] == ["B-PRODUCT", "I-PRODUCT", "O"]


def test_first_subtoken_only():
    text = "libfoo before 2.4.3"
    enc = StubTokenizer()(text)
    labels = spans_to_token_labels(
        text,
        enc["offset_mapping"],
        [Span.from_text(text, 0, 6, "PRODUCT")],
        label_all_subtokens=False,
    )
    assert tags(labels)[1:5] == ["B-PRODUCT", "-", "O", "-"]


@pytest.mark.parametrize("leading_space", [False, True])
@pytest.mark.parametrize("label_all_subtokens", [True, False])
def test_round_trip_recovers_exact_char_spans(leading_space, label_all_subtokens):
    enc = StubTokenizer(leading_space)(TEXT)
    offsets = enc["offset_mapping"]
    labels = spans_to_token_labels(TEXT, offsets, gold_spans(), label_all_subtokens)
    assert token_labels_to_spans(TEXT, offsets, labels) == gold_spans()


def test_round_trip_conftest_sample(advisory):
    enc = StubTokenizer(leading_space=True)(advisory.text)
    span = Span.from_text(advisory.text, advisory.text.index("before"), 38, "VERSION_EXPR")
    labels = spans_to_token_labels(advisory.text, enc["offset_mapping"], [span])
    assert token_labels_to_spans(advisory.text, enc["offset_mapping"], labels) == [span]


def test_decoding_is_lenient_about_bio_errors():
    text = "libfoo before 2.4.3"
    offsets = [(0, 0), (0, 6), (7, 13), (14, 19), (0, 0)]
    ids = [
        IGNORE_INDEX,
        LABEL2ID["I-PRODUCT"],
        LABEL2ID["I-VERSION_EXPR"],
        LABEL2ID["I-VERSION_EXPR"],
        IGNORE_INDEX,
    ]
    assert [(s.label, s.text) for s in token_labels_to_spans(text, offsets, ids)] == [
        ("PRODUCT", "libfoo"),
        ("VERSION_EXPR", "before 2.4.3"),
    ]


def test_b_tag_splits_adjacent_spans():
    text = "1.0 2.0"
    offsets = [(0, 3), (4, 7)]
    ids = [LABEL2ID["B-VERSION_EXPR"], LABEL2ID["B-VERSION_EXPR"]]
    assert [s.text for s in token_labels_to_spans(text, offsets, ids)] == ["1.0", "2.0"]


def test_tagger_with_stub_tokenizer_and_oracle_predict():
    tok = StubTokenizer(leading_space=True)

    def oracle(enc):  # a "model" that predicts the gold labels
        return spans_to_token_labels(TEXT, enc["offset_mapping"], gold_spans())

    adv = Advisory(id="CVE-2025-0002", source="nvd", published=datetime(2025, 8, 1), text=TEXT)
    result = DebertaTagger(tokenizer=tok, predict=oracle).extract(adv)
    assert result.model == "deberta-tagger"
    assert result.spans == gold_spans()
    summary = [
        (a.vendor.text if a.vendor else None, a.product.text, a.vers_range, a.fixed_version)
        for a in result.affected
    ]
    assert summary == [
        (None, "libfoo", "vers:generic/<2.4.3", "2.4.3"),
        ("Acme", "WidgetServer", "vers:generic/>=1.0.0|<1.9.0", None),
    ]


def test_tagger_without_model_or_stubs_raises(advisory):
    with pytest.raises(ValueError):
        DebertaTagger().extract(advisory)


def test_import_does_not_pull_in_ml_libraries():
    code = (
        "import sys, vulntriage.extract.tagger, vulntriage.extract.regex_baseline; "
        "assert not {'torch', 'transformers'} & set(sys.modules), 'heavy import'"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
