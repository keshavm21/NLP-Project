"""Interface for turning matches + predictions into a ranked patch queue (P5)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from vulntriage.schemas import SBOM, ExtractionResult, Match, Prediction, QueueItem


class Ranker(ABC):
    @abstractmethod
    def rank(
        self,
        matches: list[Match],
        predictions: dict[str, Prediction],
        extractions: dict[str, ExtractionResult],
        sboms: dict[str, SBOM],
    ) -> list[QueueItem]:
        """Return queue items sorted by risk_score (highest first), with evidence spans."""
