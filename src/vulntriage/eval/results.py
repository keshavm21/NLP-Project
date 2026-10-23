"""Write and read result files. Every reported number goes through `write_result`.

Format: docs/EVALUATION.md. Lead: P4.

Example:
    from vulntriage.eval import write_result, RunTimer

    with RunTimer() as t:
        metrics = evaluate(...)
    write_result(component="cwe", system="tfidf_lr", split="dev", n=len(y),
                 metrics=metrics, seed=42, config="configs/cwe/tfidf.yaml",
                 runtime_sec=t.seconds)
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from vulntriage.config import get_paths, load_splits

COMPONENTS = (
    "ingest",
    "extract",
    "linking",
    "cwe",
    "cvss",
    "exploit",
    "rank",
    "explain",
    "e2e",
    "rq4",
)


class ResultRecord(BaseModel):
    run_id: str
    component: str
    system: str
    baseline_of: str | None = None
    split: Literal["train", "dev", "test"]
    subset: str = "all"
    n: int
    metrics: dict[str, float]
    seed: int | None
    git_commit: str
    config: str | None = None
    data_snapshot: str | None = None
    runtime_sec: float | None = None
    cost_usd: float | None = None
    notes: str = ""
    created: str = Field(default_factory=lambda: date.today().isoformat())


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60]


def git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            cwd=get_paths().root,
        )
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def write_result(
    *,
    component: str,
    system: str,
    split: Literal["train", "dev", "test"],
    n: int,
    metrics: dict[str, float],
    seed: int | None,
    subset: str = "all",
    config: str | None = None,
    baseline_of: str | None = None,
    runtime_sec: float | None = None,
    cost_usd: float | None = None,
    notes: str = "",
    results_dir: Path | None = None,
) -> Path:
    """Validate and save one result file; returns its path.

    Writes results/<component>/<run_id>.json where
    run_id = <component>_<system>_<subset>_<date>_s<seed>.
    """
    if component not in COMPONENTS:
        raise ValueError(f"unknown component {component!r}; expected one of {COMPONENTS}")
    bad = {k: v for k, v in metrics.items() if not isinstance(v, int | float)}
    if bad:
        raise TypeError(f"metric values must be numbers, got {bad}")

    snapshot = load_splits().snapshot
    parts = [component, _slug(system)]
    if subset != "all":
        parts.append(_slug(subset))
    parts += [date.today().isoformat(), f"s{seed}" if seed is not None else "noseed"]
    run_id = "_".join(parts)

    record = ResultRecord(
        run_id=run_id,
        component=component,
        system=system,
        baseline_of=baseline_of,
        split=split,
        subset=subset,
        n=n,
        metrics={k: float(v) for k, v in metrics.items()},
        seed=seed,
        git_commit=git_commit(),
        config=config,
        data_snapshot=snapshot.isoformat() if snapshot else None,
        runtime_sec=runtime_sec,
        cost_usd=cost_usd,
        notes=notes,
    )
    out_dir = (results_dir or get_paths().results) / component
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{run_id}.json"
    path.write_text(record.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return path


def load_results(
    component: str | None = None, results_dir: Path | None = None
) -> list[ResultRecord]:
    """Load all result files (optionally for one component), e.g. to build report tables."""
    base = results_dir or get_paths().results
    pattern = f"{component}/*.json" if component else "*/*.json"
    return [
        ResultRecord.model_validate(json.loads(p.read_text())) for p in sorted(base.glob(pattern))
    ]


class RunTimer:
    """Context manager measuring wall-clock seconds for `runtime_sec`."""

    def __enter__(self) -> RunTimer:
        self._start = time.perf_counter()
        self.seconds = 0.0
        return self

    def __exit__(self, *exc: object) -> None:
        self.seconds = time.perf_counter() - self._start
