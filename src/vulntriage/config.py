"""Paths, config loading and the temporal split rule.

Use these helpers instead of hard-coding paths or dates.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import date, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv


def find_repo_root(start: Path | None = None) -> Path:
    """Walk up from `start` until a folder containing pyproject.toml is found."""
    here = (start or Path(__file__)).resolve()
    for folder in [here, *here.parents]:
        if (folder / "pyproject.toml").exists():
            return folder
    raise RuntimeError("Could not find repo root (no pyproject.toml above this file).")


@dataclass(frozen=True)
class Paths:
    root: Path

    @property
    def configs(self) -> Path:
        return self.root / "configs"

    @property
    def data(self) -> Path:
        return self.root / "data"

    @property
    def raw(self) -> Path:
        return self.data / "raw"

    @property
    def processed(self) -> Path:
        return self.data / "processed"

    @property
    def silver(self) -> Path:
        return self.processed / "silver"

    @property
    def gold(self) -> Path:
        return self.data / "gold"

    @property
    def sboms(self) -> Path:
        return self.data / "sboms"

    @property
    def models(self) -> Path:
        return self.root / "models"

    @property
    def results(self) -> Path:
        return self.root / "results"

    def raw_source(self, source: str) -> Path:
        """Folder for one source's downloads, e.g. data/raw/nvd/ (created if missing)."""
        path = self.raw / source
        path.mkdir(parents=True, exist_ok=True)
        return path

    def model_dir(self, component: str, run_id: str) -> Path:
        path = self.models / component / run_id
        path.mkdir(parents=True, exist_ok=True)
        return path


@lru_cache(maxsize=1)
def get_paths() -> Paths:
    return Paths(root=find_repo_root())


def load_env() -> None:
    """Load variables from .env at the repo root (NVD_API_KEY, ...)."""
    load_dotenv(get_paths().root / ".env")


def get_secret(name: str, required: bool = True) -> str | None:
    load_env()
    value = os.environ.get(name) or None
    if required and value is None:
        raise RuntimeError(f"{name} is not set. Copy .env.example to .env and fill it in.")
    return value


def load_yaml(path: str | Path) -> dict[str, Any]:
    """Load a YAML file; relative paths are resolved from the repo root."""
    p = Path(path)
    if not p.is_absolute():
        p = get_paths().root / p
    with p.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# ---------------------------------------------------------------- temporal split


def _to_date(value: Any) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


@dataclass(frozen=True)
class SplitConfig:
    train_end: date
    dev_start: date
    dev_end: date
    test_start: date
    snapshot: date | None  # test window ends here (None = not set yet)

    def assign(self, published: datetime | date) -> str | None:
        """Return 'train' | 'dev' | 'test', or None if outside every window.

        All boundaries are inclusive. This is the ONLY place the split rule lives.
        """
        d = _to_date(published)
        if d <= self.train_end:
            return "train"
        if self.dev_start <= d <= self.dev_end:
            return "dev"
        if d >= self.test_start and (self.snapshot is None or d <= self.snapshot):
            return "test"
        return None

    def usable_for_training(self, published: datetime | date) -> bool:
        """True only for train-window items. Use for indexes, vocabularies, alias mining."""
        return self.assign(published) == "train"


def load_splits(path: str | Path = "configs/splits.yaml") -> SplitConfig:
    cfg = load_yaml(path)
    split = SplitConfig(
        train_end=_to_date(cfg["train"]["end"]),
        dev_start=_to_date(cfg["dev"]["start"]),
        dev_end=_to_date(cfg["dev"]["end"]),
        test_start=_to_date(cfg["test"]["start"]),
        snapshot=_to_date(cfg.get("snapshot_date")),
    )
    if not (split.train_end < split.dev_start <= split.dev_end < split.test_start):
        raise ValueError("splits.yaml windows overlap or are out of order")
    return split
