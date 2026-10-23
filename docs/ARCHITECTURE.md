# Architecture

## Data flow

```
                     ┌──────────────────────────────────────────────┐
 NVD API / CVE JSON5 │ ingest/                                      │
 GitHub Advisory DB  │  fetchers → normalize → dedup → Advisory     │──► Postgres (advisories)
 OSV / KEV / EPSS    │  benchmark builder (time split, silver/gold) │──► data/processed/
 vendor bulletins    └──────────────────────────────────────────────┘
                                         │ Advisory
                                         ▼
                     ┌──────────────────────────────────────────────┐
                     │ extract/                                     │
                     │  span tagger (PRODUCT, VENDOR, VERSION_EXPR, │
                     │  FIXED_VERSION) → version grammar → ranges   │
                     └──────────────────────────────────────────────┘
                                         │ ExtractionResult
                                         ▼
                     ┌──────────────────────────────────────────────┐
                     │ linking/                                     │
                     │  candidates (BM25 + dense/FAISS) →           │
                     │  cross-encoder rerank → NIL threshold        │
                     └──────────────────────────────────────────────┘
                                         │ LinkedProduct[]
             ┌───────────────────────────┤
             ▼                           ▼
 ┌────────────────────────┐   ┌──────────────────────────────────┐
 │ classify/              │   │ match/                           │
 │  CWE (hierarchical)    │   │  SBOM (CycloneDX/SPDX) parser    │
 │  CVSS (multi-task)     │   │  purl/CPE join + univers ranges  │
 │  exploitation signals  │   └──────────────────────────────────┘
 │  calibration/conformal │                  │ Match[]
 └────────────────────────┘                  │
             │ Prediction                    │
             └──────────────┬────────────────┘
                            ▼
                ┌──────────────────────────────┐
                │ rank/                        │
                │  risk score + routing        │
                │  grounded explanation +      │
                │  verifier                    │
                └──────────────────────────────┘
                            │ QueueItem[]
                            ▼
                api/ (FastAPI)  ──►  web/ (React dashboard)
```

## Modules

### `ingest/` (P1)
- One fetcher per source; each writes raw files to `data/raw/<source>/` and is idempotent (re-running skips what's already downloaded).
- `normalize.py` converts every source into the common `Advisory` schema.
- `dedup.py` merges records describing the same vulnerability across sources (shared CVE/GHSA aliases first, then text similarity for bulletins without IDs).
- `benchmark.py` builds train/dev/test splits by `published` date from `configs/splits.yaml`, and creates silver labels (see `docs/DATA.md`).

### `extract/` (P2)
- `tagger.py`: token-classification model (BIO tags) over advisory text. Labels: `VENDOR`, `PRODUCT`, `VERSION_EXPR`, `FIXED_VERSION`.
- `version_grammar.py`: deterministic parser turning `VERSION_EXPR` strings into structured ranges. Families to handle: "before X", "prior to X", "through X", "up to (and including) X", "X and earlier", "X.x before Y", "from A to B", "A through B", "versions A, B and C", "fixed in X", "all versions".
- `llm_extractor.py`: LoRA-tuned small LLM that emits the same JSON (comparison system, not the default).
- Output always goes through `univers` to produce canonical `VersionRange` strings (e.g., `vers:pypi/>=3.0.0|<3.1.1`).

### `linking/` (P3)
- `index.py`: builds the candidate index over CPE dictionary products + package names (PyPI, npm, Maven), with aliases.
- `candidates.py`: BM25 + bi-encoder retrieval, top-k union.
- `rerank.py`: cross-encoder scoring (mention + context sentence vs candidate description).
- `nil.py`: threshold / classifier deciding NIL ("not in our identifier space").
- Alias mining: records containing both a package name and a CPE provide (alias → identifier) pairs.

### `classify/` (P4)
- `cwe.py`: hierarchical CWE classifier; label descriptions from the CWE catalog used as extra input / for zero-shot tail classes.
- `cvss.py`: multi-task head predicting the 8 CVSS v3.1 base metrics (AV, AC, PR, UI, S, C, I, A); base score computed from predicted vector with the official formula.
- `exploit.py`: classifier for exploitation signals in text ("actively exploited", "PoC available").
- `calibrate.py`: temperature scaling + conformal prediction sets; outputs calibrated probabilities used by `rank/`.

### `match/` (P5)
- Parses CycloneDX / SPDX JSON SBOMs generated with Syft.
- Joins on purl (preferred) or CPE, then checks version containment via `univers`.

### `rank/` (P5)
- `score.py`: heuristic score (CVSS × KEV × EPSS × asset criticality × confidence) plus an optional learned ranker.
- `routing.py`: items below a confidence threshold go to the "needs review" lane.
- `explain.py`: generates a short analyst note from extracted fields only; `verify.py` rejects any sentence not supported by a field or evidence span.

### `eval/` (shared)
- Metric functions for every component, the replay harness, and the result-file writer. See `docs/EVALUATION.md`.

### `api/` + `web/` (P5)
- FastAPI endpoints: `POST /advisories/analyze` (paste-in), `GET /queue?sbom=...`, `GET /items/{id}`, `POST /items/{id}/feedback`.
- React dashboard: queue view, item view with highlighted evidence spans, "paste an advisory" box, replay mode.

## Core schemas (`src/vulntriage/schemas.py`)

These are the contracts between modules. **The code in `src/vulntriage/schemas.py` is the source of truth** (it also defines `SBOM`, `SBOMComponent` and an `Advisory.split` field); the sketch below is for reading. Change only with a line in `docs/DECISIONS.md`.

Each module implements an interface in its `base.py`, and `src/vulntriage/pipeline.py` wires them together.

```python
from datetime import datetime
from pydantic import BaseModel


class Advisory(BaseModel):
    id: str  # canonical ID (CVE-..., else GHSA-..., else source-specific)
    aliases: list[str]  # all known IDs across sources
    source: str  # "nvd" | "cve5" | "ghsa" | "osv" | "bulletin" | ...
    published: datetime
    modified: datetime | None
    title: str | None
    text: str  # the description used as model input
    references: list[str]


class Span(BaseModel):
    start: int  # char offsets into Advisory.text
    end: int
    label: str  # VENDOR | PRODUCT | VERSION_EXPR | FIXED_VERSION
    text: str


class AffectedItem(BaseModel):
    vendor: Span | None
    product: Span
    version_spans: list[Span]
    vers_range: str | None  # univers "vers:" string; None if unparseable
    fixed_version: str | None
    confidence: float


class ExtractionResult(BaseModel):
    advisory_id: str
    spans: list[Span]
    affected: list[AffectedItem]
    model: str  # which extractor produced this


class LinkedProduct(BaseModel):
    mention: Span
    identifier: str | None  # "cpe:2.3:a:..." or "pkg:pypi/..."; None = NIL
    score: float
    candidates: list[tuple[str, float]]  # top-k for debugging/UI


class Prediction(BaseModel):
    advisory_id: str
    cwe: list[tuple[str, float]]  # ranked (CWE-ID, calibrated prob)
    cwe_set: list[str]  # conformal prediction set
    cvss_vector: str  # "CVSS:3.1/AV:N/AC:L/..."
    cvss_metric_probs: dict[str, dict[str, float]]
    cvss_base_score: float
    exploitation: float  # prob. text indicates active exploitation
    kev: bool
    epss: float | None


class Match(BaseModel):
    advisory_id: str
    sbom_id: str
    component_purl: str
    component_version: str
    affected: bool
    vers_range: str


class QueueItem(BaseModel):
    advisory_id: str
    sbom_id: str
    component_purl: str
    risk_score: float
    needs_review: bool
    recommended_version: str | None
    explanation: str
    evidence: list[Span]
```

## Storage

- Postgres for advisories, predictions and queue items (SQLite is fine for local dev; keep it behind a small repository layer).
- FAISS index files in `models/linking/`.
- Checkpoints in `models/<component>/<run_id>/`.

## Models (defaults; record changes in DECISIONS.md)

| Use | Default | Why |
|---|---|---|
| Encoder backbone (tagging, classification) | `microsoft/deberta-v3-base` | Strong token/sequence classification, fits a single GPU |
| Security-domain encoder (comparison) | a security-domain BERT (e.g., SecureBERT) | Domain adaptation experiment |
| Bi-encoder (linking) | a sentence-transformers model (e.g., `all-MiniLM-L6-v2` → upgrade if needed) | Fast candidate retrieval |
| Cross-encoder (linking) | `cross-encoder/ms-marco-MiniLM-L-6-v2`, fine-tuned | Reranking |
| Small LLM (extraction comparison, explanations) | a ~1.5–8B open instruct model with LoRA | Runs locally; no proprietary API dependency |
| Large-LLM baseline | one strong open or API model, used only as a baseline | RQ4 comparison |
