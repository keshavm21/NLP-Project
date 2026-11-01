"""Tests for gold evaluation datasets, validation, agreement, and sampling (P1)."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from vulntriage.config import get_paths
from vulntriage.ingest.gold import (
    GoldExtractionRecord,
    GoldLinkingRecord,
    GoldSpan,
    compute_cohens_kappa,
    compute_span_f1,
    sample_test_items_for_annotation,
    validate_gold_file,
)
from vulntriage.schemas import Advisory


def test_gold_span_validation():
    # Valid span
    span = GoldSpan(start=0, end=6, label="VENDOR", text="Apache")
    assert span.text == "Apache"

    # Reject end <= start
    with pytest.raises(ValidationError):
        GoldSpan(start=5, end=5, label="VENDOR", text="")

    # Reject text length mismatch
    with pytest.raises(ValidationError):
        GoldSpan(start=0, end=5, label="VENDOR", text="toolong")


def test_gold_extraction_record_offset_validation():
    text = "Apache Struts before 2.5.30 is vulnerable."
    # Valid record
    rec = GoldExtractionRecord(
        advisory_id="CVE-2025-0001",
        text=text,
        spans=[
            GoldSpan(start=0, end=6, label="VENDOR", text="Apache"),
            GoldSpan(start=7, end=13, label="PRODUCT", text="Struts"),
            GoldSpan(start=14, end=27, label="VERSION_EXPR", text="before 2.5.30"),
        ],
        vers_range="vers:maven/<2.5.30",
        fixed_version="2.5.30",
        verified=True,
    )
    assert rec.advisory_id == "CVE-2025-0001"

    # Reject if text at offsets does not match span text
    with pytest.raises(ValidationError, match="Span text mismatch"):
        GoldExtractionRecord(
            advisory_id="CVE-2025-0001",
            text=text,
            spans=[GoldSpan(start=0, end=6, label="VENDOR", text="WrongX")],
        )


def test_gold_linking_record_validation():
    rec = GoldLinkingRecord(
        advisory_id="CVE-2025-0001",
        mention="Struts",
        start=7,
        end=13,
        context="Apache Struts before 2.5.30 is vulnerable.",
        gold_identifier="pkg:maven/org.apache.struts/struts2-core",
        is_nil=False,
        annotator_id="Rishi Kharya",
        verified=True,
    )
    assert rec.is_nil is False
    assert rec.gold_identifier == "pkg:maven/org.apache.struts/struts2-core"

    # NIL record must have gold_identifier=None
    nil_rec = GoldLinkingRecord(
        advisory_id="CVE-2025-0002",
        mention="CustomCorpApp",
        start=0,
        end=13,
        context="CustomCorpApp is vulnerable.",
        gold_identifier=None,
        is_nil=True,
        annotator_id="Rishi Kharya",
        verified=True,
    )
    assert nil_rec.is_nil is True

    # Reject contradiction: is_nil=True with non-None identifier
    with pytest.raises(ValidationError):
        GoldLinkingRecord(
            advisory_id="CVE-2025-0003",
            mention="app",
            start=0,
            end=3,
            context="app is vulnerable.",
            gold_identifier="pkg:pypi/app",
            is_nil=True,
            annotator_id="test",
        )


def test_compute_span_f1():
    # Annotator 1 and Annotator 2 have identical spans
    ann1 = [(0, 6, "VENDOR"), (7, 13, "PRODUCT")]
    ann2 = [(0, 6, "VENDOR"), (7, 13, "PRODUCT")]
    res = compute_span_f1(ann1, ann2)
    assert res["f1"] == 1.0

    # Partial overlap
    ann3 = [(0, 6, "VENDOR"), (7, 15, "PRODUCT")]  # wrong end offset
    res2 = compute_span_f1(ann1, ann3)
    assert res2["precision"] == 0.5
    assert res2["recall"] == 0.5
    assert res2["f1"] == 0.5

    # Completely disjoint
    ann4 = [(20, 30, "VERSION_EXPR")]
    res3 = compute_span_f1(ann1, ann4)
    assert res3["f1"] == 0.0


def test_compute_cohens_kappa():
    # Perfect agreement
    labels_a = [1, 0, 1, 1, 0]
    labels_b = [1, 0, 1, 1, 0]
    assert compute_cohens_kappa(labels_a, labels_b) == 1.0

    # High agreement
    l1 = [1, 0, 1, 0, 1, 0, 1, 0, 1, 0]
    l2 = [1, 0, 1, 0, 1, 0, 1, 0, 0, 0]
    kappa = compute_cohens_kappa(l1, l2)
    assert kappa > 0.7


def test_sample_test_items_workflow():
    advisories = [
        Advisory(
            id=f"CVE-2025-{i:04d}",
            source="nvd",
            published=datetime(2025, 7, 10, tzinfo=timezone.utc),
            text=f"Advisory text {i}",
        )
        for i in range(150)
    ]
    sample_res = sample_test_items_for_annotation(
        advisories, target_count=100, double_annotate_count=20, seed=42
    )
    assert sample_res["total_sampled"] == 100
    assert sample_res["double_annotated_count"] == 20
    assert len(sample_res["double_pairs"]) == 20
    assert len(sample_res["assignments"]) == 5  # all 5 members


def test_existing_gold_files_pass_validation():
    paths = get_paths()
    ext_path = paths.gold / "extraction.jsonl"
    link_path = paths.gold / "linking.jsonl"
    bull_path = paths.gold / "bulletins.jsonl"

    if ext_path.exists():
        cnt, errs = validate_gold_file(ext_path, "extraction")
        assert len(errs) == 0, f"Extraction errors: {errs}"
        assert cnt > 0

    if link_path.exists():
        cnt, errs = validate_gold_file(link_path, "linking")
        assert len(errs) == 0, f"Linking errors: {errs}"
        assert cnt > 0

    if bull_path.exists():
        cnt, errs = validate_gold_file(bull_path, "bulletin")
        assert len(errs) == 0, f"Bulletin errors: {errs}"
        assert cnt > 0
