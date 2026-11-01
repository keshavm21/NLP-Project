"""Tests for span alignment and silver extraction label generation (P1)."""

from vulntriage.ingest.align import align_advisory
from vulntriage.schemas import Span


def test_align_exact_match():
    text = "Apache Struts versions 2.0.0 through 2.5.32 are vulnerable. Fixed in 2.5.33."
    prods = [
        {
            "product": "Struts",
            "vendor": "Apache",
            "versions": ["2.0.0 through 2.5.32"],
            "fixed_versions": ["2.5.33"],
        }
    ]
    spans = align_advisory("CVE-2024-001", text, prods)
    assert spans is not None
    assert len(spans) == 4

    labels = {s.label: s.text for s in spans}
    assert labels["VENDOR"] == "Apache"
    assert labels["PRODUCT"] == "Struts"
    assert labels["VERSION_EXPR"] == "2.0.0 through 2.5.32"
    assert labels["FIXED_VERSION"] == "2.5.33"

    for s in spans:
        span_obj = s.to_span(text)
        assert isinstance(span_obj, Span)
        assert text[span_obj.start : span_obj.end] == span_obj.text


def test_align_case_insensitive():
    text = "In REQUESTS before 2.32.0, SSL certificate verification is flawed."
    prods = [{"product": "requests", "versions": ["before 2.32.0"]}]
    spans = align_advisory("CVE-2024-002", text, prods)
    assert spans is not None
    assert len(spans) == 2
    prod_span = next(s for s in spans if s.label == "PRODUCT")
    assert prod_span.text == "REQUESTS"
    assert prod_span.alignment_method == "ci_exact"


def test_align_normalized_punctuation():
    text = "A flaw in log4j_core versions before 2.15.0 allows JNDI injection."
    prods = [{"product": "log4j-core", "versions": ["before 2.15.0"]}]
    spans = align_advisory("CVE-2024-003", text, prods)
    assert spans is not None
    prod_span = next(s for s in spans if s.label == "PRODUCT")
    assert prod_span.text == "log4j_core"
    assert prod_span.alignment_method == "normalized"
    assert text[prod_span.start : prod_span.end] == "log4j_core"


def test_align_drops_advisory_when_product_missing():
    # If the structured product is NOT mentioned in the text, drop the advisory
    text = "A severe buffer overflow was discovered in an undisclosed networking component."
    prods = [{"product": "openssl", "versions": ["1.1.1"]}]
    spans = align_advisory("CVE-2024-004", text, prods)
    assert spans is None


def test_align_handles_multiple_products():
    text = "Vulnerabilities in flask before 3.0.0 and werkzeug before 3.0.1 allow session fixation."
    prods = [
        {"product": "flask", "versions": ["before 3.0.0"]},
        {"product": "werkzeug", "versions": ["before 3.0.1"]},
    ]
    spans = align_advisory("CVE-2024-005", text, prods)
    assert spans is not None
    # Both products and their version expressions found
    prod_names = {s.text for s in spans if s.label == "PRODUCT"}
    assert prod_names == {"flask", "werkzeug"}
