import pytest
from pydantic import ValidationError

from vulntriage.schemas import Advisory, Span


def test_span_from_text(advisory: Advisory):
    start = advisory.text.index("libfoo")
    span = Span.from_text(advisory.text, start, start + len("libfoo"), "PRODUCT")
    assert span.text == "libfoo"


def test_span_rejects_bad_offsets():
    with pytest.raises(ValidationError):
        Span(start=5, end=5, label="PRODUCT", text="")
    with pytest.raises(ValidationError):
        Span(start=0, end=3, label="PRODUCT", text="toolong")


def test_span_rejects_unknown_label():
    with pytest.raises(ValidationError):
        Span(start=0, end=3, label="SOFTWARE", text="abc")


def test_advisory_roundtrip(advisory: Advisory):
    assert Advisory.model_validate_json(advisory.model_dump_json()) == advisory
