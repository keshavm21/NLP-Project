"""Interface for weakness/severity/exploitation predictors (P4)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from vulntriage.schemas import Advisory, Prediction


class Classifier(ABC):
    name: str

    @abstractmethod
    def predict(self, advisory: Advisory) -> Prediction:
        """Return calibrated CWE ranking, CVSS vector (+ per-metric probs), exploitation prob."""

    def predict_batch(self, advisories: Iterable[Advisory]) -> list[Prediction]:
        return [self.predict(a) for a in advisories]
