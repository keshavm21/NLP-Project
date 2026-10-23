"""Interface every linker implements (P3): fuzzy, BM25, bi-encoder, + reranker, ..."""

from __future__ import annotations

from abc import ABC, abstractmethod

from vulntriage.schemas import Advisory, LinkedProduct, Span


class Linker(ABC):
    name: str

    @abstractmethod
    def link(self, mention: Span, advisory: Advisory) -> LinkedProduct:
        """Resolve a PRODUCT mention to a purl/CPE, or identifier=None for NIL.

        `advisory` gives context (sentence, ecosystem hints). Always fill `candidates`
        with the top-k (identifier, score) pairs.
        """

    def link_batch(self, items: list[tuple[Span, Advisory]]) -> list[LinkedProduct]:
        return [self.link(m, a) for m, a in items]
