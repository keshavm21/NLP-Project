"""Read/write JSONL files of Pydantic models (the format used for all processed data)."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

M = TypeVar("M", bound=BaseModel)


def write_jsonl(path: str | Path, items: Iterable[BaseModel | dict]) -> int:
    """Write one JSON object per line. Returns the number of lines written."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with p.open("w", encoding="utf-8") as f:
        for item in items:
            line = item.model_dump_json() if isinstance(item, BaseModel) else json.dumps(item)
            f.write(line + "\n")
            n += 1
    return n


def iter_jsonl(path: str | Path, model: type[M]) -> Iterator[M]:
    """Stream a JSONL file as validated models (memory-friendly for large files)."""
    with Path(path).open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield model.model_validate_json(line)
            except Exception as exc:  # include location to make bad data easy to find
                raise ValueError(f"{path}:{lineno}: {exc}") from exc


def read_jsonl(path: str | Path, model: type[M]) -> list[M]:
    return list(iter_jsonl(path, model))


def read_jsonl_dicts(path: str | Path) -> list[dict]:
    with Path(path).open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]
