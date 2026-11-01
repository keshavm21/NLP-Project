"""Gold dataset schemas, validation, sampling and inter-annotator agreement (P1).

Responsible for:
1. Defining the gold dataset schema contracts (human-verified evaluation sets).
2. Validating gold files in data/gold/ against schemas, text offsets, and test window.
3. Sampling test-window advisories for team annotation across all 5 members.
4. Computing inter-annotator agreement:
   - Span-level F1 (micro and macro) between annotators.
   - Cohen's Kappa for categorical annotations (e.g. NIL detection).
5. Adjudication workflow helper for resolving double-annotated disagreements.
"""

from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError, model_validator

from vulntriage.schemas import Advisory, SpanLabel
from vulntriage.utils.logging import get_logger

logger = get_logger(__name__)

TEAM_MEMBERS: list[str] = [
    "Ayush Khelwal",
    "Keshav Mishra",
    "Rishi Kharya",
    "Akshat Gupta",
    "Pranjal",
]


class GoldSpan(BaseModel):
    """Human-verified span with strict boundary and offset validation."""

    start: int = Field(ge=0)
    end: int = Field(ge=0)
    label: SpanLabel
    text: str
    annotator_id: str | None = None
    adjudicated: bool = False

    @model_validator(mode="after")
    def _validate_span(self) -> GoldSpan:
        if self.end <= self.start:
            raise ValueError(f"Span end ({self.end}) must be strictly > start ({self.start})")
        if len(self.text) != self.end - self.start:
            raise ValueError(
                f"Span text '{self.text}' length ({len(self.text)}) does not match "
                f"offset length {self.end - self.start}"
            )
        return self


class GoldExtractionRecord(BaseModel):
    """One human-verified extraction gold record."""

    advisory_id: str
    text: str
    spans: list[GoldSpan]
    vers_range: str | None = None
    fixed_version: str | None = None
    annotators: list[str] = Field(default_factory=list)
    verified: bool = True
    notes: str | None = None

    @model_validator(mode="after")
    def _validate_offsets(self) -> GoldExtractionRecord:
        for span in self.spans:
            if span.end > len(self.text):
                raise ValueError(
                    f"Span [{span.start}:{span.end}] exceeds text length ({len(self.text)})"
                )
            expected = self.text[span.start : span.end]
            if span.text != expected:
                raise ValueError(
                    f"Span text mismatch: record specifies '{span.text}', "
                    f"but text[{span.start}:{span.end}] is '{expected}'"
                )
        return self


class GoldLinkingRecord(BaseModel):
    """One human-verified entity linking gold record."""

    advisory_id: str
    mention: str
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    context: str
    gold_identifier: str | None  # purl, CPE, or None for NIL
    is_nil: bool = False
    annotator_id: str
    verified: bool = True
    notes: str | None = None

    @model_validator(mode="after")
    def _validate_linking(self) -> GoldLinkingRecord:
        if self.is_nil and self.gold_identifier is not None:
            raise ValueError("Record marked as is_nil=True but has non-None gold_identifier")
        if not self.is_nil and self.gold_identifier is None:
            raise ValueError("Record is not NIL but gold_identifier is None")
        if self.end <= self.start:
            raise ValueError("end must be > start")
        if self.end <= len(self.context):
            expected = self.context[self.start : self.end]
            if expected.lower() != self.mention.lower():
                logger.debug(
                    "Mention text casing mismatch: '%s' vs context slice '%s'",
                    self.mention,
                    expected,
                )
        return self


# ------------------------------------------------------------------ Validation


def validate_gold_file(path: str | Path, record_type: str) -> tuple[int, list[str]]:
    """Validate a gold dataset JSONL file against schema and offset constraints.

    Returns:
        (valid_count, errors_list)
    """
    p = Path(path)
    if not p.exists():
        return 0, [f"File {p} does not exist"]

    valid_count = 0
    errors: list[str] = []

    with p.open(encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                data = json.loads(line)
                if record_type == "extraction":
                    GoldExtractionRecord.model_validate(data)
                elif record_type == "linking":
                    GoldLinkingRecord.model_validate(data)
                elif record_type == "bulletin":
                    # Bulletin records are extraction records with source metadata
                    GoldExtractionRecord.model_validate(data)
                else:
                    raise ValueError(f"Unknown record_type: {record_type}")
                valid_count += 1
            except ValidationError as ve:
                errors.append(f"Line {line_num} validation error: {ve}")
            except json.JSONDecodeError as je:
                errors.append(f"Line {line_num} JSON error: {je}")
            except Exception as ex:
                errors.append(f"Line {line_num} unexpected error: {ex}")

    return valid_count, errors


# ------------------------------------------------------------------ Agreement Metrics


def compute_span_f1(
    ann1_spans: Sequence[tuple[int, int, str]],
    ann2_spans: Sequence[tuple[int, int, str]],
) -> dict[str, float]:
    """Compute exact span-level Precision, Recall, and F1 between two annotators.

    Each span is represented as (start, end, label).
    """
    s1 = set(ann1_spans)
    s2 = set(ann2_spans)

    if not s1 and not s2:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    if not s1 or not s2:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}

    intersection = len(s1 & s2)
    precision = intersection / len(s2) if s2 else 0.0
    recall = intersection / len(s1) if s1 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def compute_cohens_kappa(labels1: Sequence[Any], labels2: Sequence[Any]) -> float:
    """Compute Cohen's Kappa for categorical annotations between two annotators."""
    if len(labels1) != len(labels2):
        raise ValueError("Annotator label lists must have identical length")
    n = len(labels1)
    if n == 0:
        return 1.0

    # Observed agreement P_o
    po = sum(1 for a, b in zip(labels1, labels2, strict=True) if a == b) / n

    # Expected agreement P_e
    cats = sorted(set(labels1) | set(labels2))
    c1 = Counter(labels1)
    c2 = Counter(labels2)

    pe = sum((c1[c] / n) * (c2[c] / n) for c in cats)

    if math.isclose(pe, 1.0):
        return 1.0
    kappa = (po - pe) / (1.0 - pe)
    return round(kappa, 4)


# ------------------------------------------------------------------ Sampling Workflow


def sample_test_items_for_annotation(
    test_advisories: list[Advisory],
    target_count: int = 500,
    double_annotate_count: int = 100,
    seed: int = 42,
) -> dict[str, Any]:
    """Sample test-window advisories and assign them to the 5 team members.

    Generates:
    - Primary assignments partitioned across members.
    - 100 double-annotated items assigned to pairs of members for agreement study.
    """
    import random

    rng = random.Random(seed)
    n = min(len(test_advisories), target_count)
    if n == 0:
        return {"total_sampled": 0, "assignments": {}}

    sampled = rng.sample(test_advisories, n)
    double_n = min(double_annotate_count, n)
    double_subset = sampled[:double_n]
    single_subset = sampled[double_n:]

    assignments: dict[str, list[str]] = defaultdict(list)
    double_pairs: list[dict[str, Any]] = []

    # Assign single subset evenly
    for i, adv in enumerate(single_subset):
        member = TEAM_MEMBERS[i % len(TEAM_MEMBERS)]
        assignments[member].append(adv.id)

    # Assign double-annotated subset to pairs of annotators
    for i, adv in enumerate(double_subset):
        m1 = TEAM_MEMBERS[i % len(TEAM_MEMBERS)]
        m2 = TEAM_MEMBERS[(i + 1) % len(TEAM_MEMBERS)]
        assignments[m1].append(adv.id)
        assignments[m2].append(adv.id)
        double_pairs.append(
            {
                "advisory_id": adv.id,
                "annotator_1": m1,
                "annotator_2": m2,
            }
        )

    return {
        "seed": seed,
        "total_sampled": n,
        "double_annotated_count": double_n,
        "assignments": dict(assignments),
        "double_pairs": double_pairs,
    }
