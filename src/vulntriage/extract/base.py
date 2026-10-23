"""Interface every extractor implements (P2): regex baseline, tagger, LLM, ..."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from vulntriage.schemas import Advisory, ExtractionResult


class Extractor(ABC):
    name: str

    @abstractmethod
    def extract(self, advisory: Advisory) -> ExtractionResult:
        """Find VENDOR / PRODUCT / VERSION_EXPR / FIXED_VERSION spans and affected items.

        Spans are character offsets into advisory.text. If a version phrase can't be
        normalized, set AffectedItem.vers_range = None (never guess).
        """

    def extract_batch(self, advisories: Iterable[Advisory]) -> list[ExtractionResult]:
        """Override for batched GPU inference."""
        return [self.extract(a) for a in advisories]
