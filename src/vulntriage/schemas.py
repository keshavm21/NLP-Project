"""Shared data contracts between modules.

Every module reads and writes these models; no ad-hoc dicts between modules.
Change a field only after discussing it with the team and adding a row to
docs/DECISIONS.md. Lead: P5.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

SpanLabel = Literal["VENDOR", "PRODUCT", "VERSION_EXPR", "FIXED_VERSION"]
Split = Literal["train", "dev", "test"]
SPAN_LABELS: tuple[str, ...] = ("VENDOR", "PRODUCT", "VERSION_EXPR", "FIXED_VERSION")
CVSS_METRICS: tuple[str, ...] = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class Advisory(BaseModel):
    """One vulnerability advisory, normalized from any source (P1)."""

    id: str  # canonical ID: CVE-..., else GHSA-..., else source-specific
    aliases: list[str] = Field(default_factory=list)  # all known IDs across sources
    source: str  # "nvd" | "cve5" | "ghsa" | "osv" | "bulletin" | ...
    published: datetime
    modified: datetime | None = None
    title: str | None = None
    text: str  # the description used as model input
    references: list[str] = Field(default_factory=list)
    split: Split | None = None  # assigned by the benchmark builder


class Span(BaseModel):
    """A labeled character span inside Advisory.text."""

    start: int = Field(ge=0)
    end: int = Field(ge=0)
    label: SpanLabel
    text: str

    @model_validator(mode="after")
    def _check_order(self) -> Span:
        if self.end <= self.start:
            raise ValueError(f"span end ({self.end}) must be > start ({self.start})")
        if len(self.text) != self.end - self.start:
            raise ValueError("span text length does not match end - start")
        return self

    @classmethod
    def from_text(cls, text: str, start: int, end: int, label: SpanLabel) -> Span:
        """Build a span from offsets into `text` (keeps `text` field consistent)."""
        return cls(start=start, end=end, label=label, text=text[start:end])


class AffectedItem(BaseModel):
    """One affected product with its version range (P2)."""

    vendor: Span | None = None
    product: Span
    version_spans: list[Span] = Field(default_factory=list)
    vers_range: str | None = None  # univers "vers:" string; None if unparseable
    fixed_version: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class ExtractionResult(BaseModel):
    advisory_id: str
    spans: list[Span] = Field(default_factory=list)
    affected: list[AffectedItem] = Field(default_factory=list)
    model: str  # which extractor produced this


class LinkedProduct(BaseModel):
    """A product mention resolved to an identifier, or NIL (P3)."""

    mention: Span
    identifier: str | None  # "cpe:2.3:a:..." or "pkg:pypi/..."; None = NIL
    score: float
    candidates: list[tuple[str, float]] = Field(default_factory=list)  # top-k, for UI/debugging

    @property
    def is_nil(self) -> bool:
        return self.identifier is None


class Prediction(BaseModel):
    """Weakness, severity and exploitation predictions (P4)."""

    advisory_id: str
    cwe: list[tuple[str, float]] = Field(default_factory=list)  # ranked (CWE-ID, calibrated prob)
    cwe_set: list[str] = Field(default_factory=list)  # conformal prediction set
    cvss_vector: str | None = None  # "CVSS:3.1/AV:N/AC:L/..."
    cvss_metric_probs: dict[str, dict[str, float]] = Field(default_factory=dict)
    cvss_base_score: float | None = Field(default=None, ge=0.0, le=10.0)
    exploitation: float | None = Field(default=None, ge=0.0, le=1.0)
    kev: bool = False
    epss: float | None = Field(default=None, ge=0.0, le=1.0)


class SBOMComponent(BaseModel):
    purl: str | None = None
    cpe: str | None = None
    name: str
    version: str
    ecosystem: str | None = None


class SBOM(BaseModel):
    id: str  # e.g. "github.com/org/repo@<commit>"
    components: list[SBOMComponent]
    criticality: float = Field(default=1.0, ge=0.0)  # asset weight used in ranking


class Match(BaseModel):
    """An advisory matched against one SBOM component (P5)."""

    advisory_id: str
    sbom_id: str
    component_purl: str
    component_version: str
    affected: bool
    vers_range: str


class QueueItem(BaseModel):
    """One entry in the ranked patch queue (P5)."""

    advisory_id: str
    sbom_id: str
    component_purl: str
    risk_score: float
    needs_review: bool
    recommended_version: str | None = None
    explanation: str = ""
    evidence: list[Span] = Field(default_factory=list)
