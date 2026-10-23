"""Interface for matching linked, version-ranged products against an SBOM (P5)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from vulntriage.schemas import SBOM, AffectedItem, LinkedProduct, Match


class Matcher(ABC):
    @abstractmethod
    def match(
        self,
        advisory_id: str,
        affected: list[tuple[LinkedProduct, AffectedItem]],
        sbom: SBOM,
    ) -> list[Match]:
        """Join on purl (then CPE) and check version containment with `univers`."""
