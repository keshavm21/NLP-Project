"""Interface every data source implements (P1)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

from vulntriage.config import get_paths
from vulntriage.schemas import Advisory


class Source(ABC):
    """One upstream source (nvd, cve5, ghsa, osv, kev, epss, ...).

    `download` must be idempotent: skip files that already exist, so re-running is cheap.
    `iter_advisories` reads the raw files and yields normalized Advisory objects
    (sources without advisory text, like KEV/EPSS, may leave it unimplemented).
    """

    name: str

    @property
    def raw_dir(self) -> Path:
        return get_paths().raw_source(self.name)

    @abstractmethod
    def download(self, force: bool = False) -> None: ...

    def iter_advisories(self) -> Iterator[Advisory]:
        raise NotImplementedError(f"{self.name} does not produce advisories")
