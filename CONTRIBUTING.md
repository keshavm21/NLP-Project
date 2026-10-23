# Contributing

How we work together on this repo. Read once at the start; skim again before your first PR.

## Git workflow

- `main` is always working: tests pass, pipeline runs.
- Branch per task: `<role>/<short-name>`, e.g. `p2/version-grammar`, `p4/cvss-multitask`.
- Open a **pull request** into `main`; at least **one other member reviews** before merging. Small PRs (< ~400 lines) get reviewed faster.
- Commit messages: imperative, specific — `Add CVSS base-score formula with tests`, not `update`.
- Pull `main` often to avoid painful merges.
- Never force-push to `main`.

## What may and may not be committed

| Commit | Never commit |
|---|---|
| Code, tests, configs | `data/raw/`, `data/processed/` (rebuilt by `make`) |
| `results/**/*.json`, `results/**/ERRORS.md` | Model checkpoints / weights |
| Gold-set files in `data/gold/` (small, hand-made) | API keys, `.env` |
| Docs | Large notebooks with outputs (clear outputs first) |
| SBOM manifest (`data/sboms/manifest.json`) | Downloaded exploit code (we never download any) |

If you need to share a checkpoint, upload it to the team drive and put the link + run ID in the PR.

## Code style

- Python 3.11, type hints on public functions.
- Cross-module data uses the Pydantic models in `src/vulntriage/schemas.py` — no ad-hoc dicts between modules.
- Formatting and linting: `ruff format` and `ruff check` (`make lint`). CI rejects PRs that fail.
- No hard-coded paths or hyperparameters: put them in `configs/<component>/*.yaml`.
- Fix random seeds and log them.
- Notebooks are fine for exploration in `notebooks/<your-role>/`, but anything that produces a reported number must be a script run via `make`.

## Adding your code

- Implement the interface in your module's `base.py` (e.g. `class DebertaCWE(Classifier)`), so `pipeline.py` can use it unchanged.
- Each Makefile step points to a module listed by `make status`. Create that file with a `main(argv: list[str]) -> int` function.
- Load paths with `get_paths()`, secrets with `get_secret("NVD_API_KEY")`, configs with `load_yaml(...)`, splits with `load_splits()` — all in `vulntriage.config`.
- Save data as JSONL of schema objects with `vulntriage.jsonl.write_jsonl` / `read_jsonl`.
- Start every script with `set_seed(seed)` and log with `get_logger(__name__)` (`vulntriage.utils`).
- Heavy imports (torch, transformers) go inside your module, not in shared files, so CI stays light.

## Tests

- Tests live in `tests/<module>/`, mirroring `src/vulntriage/`.
- Every new public function gets at least one test. Deterministic code (version grammar, CVSS formula, version matching) gets thorough tests — it's cheap to test and costly to get wrong.
- Tests must not call remote APIs. Use small fixture files.
- `make test` must pass before you open a PR.

## Reporting results

Every number that may go in the report is written by `src/vulntriage/eval/` to `results/<component>/<run_id>.json` (format in `docs/EVALUATION.md`).

- `run_id`: `<component>_<system>_<date>_s<seed>`.
- Run main systems with 3 seeds.
- Commit result files in the same PR as the code that produced them.
- Test-set numbers only after model selection on dev is finished. If you look at test results and then change the model, say so in `notes`.

## Making decisions

Anything that affects other members — a schema change, a split date, a dataset choice, a label definition, a threshold — goes in `docs/DECISIONS.md` as a new row. Raise it in the team chat first. Don't edit or delete old rows; add a new row that supersedes them.

## Annotation

Follow `docs/annotation_guidelines.md`. When unsure, don't guess: mark the item `unsure` and bring it to the weekly sync.

## Ethics and scope

We build a **defensive** tool on public data. We do not download, write or generate exploit code, and we don't scan systems we don't own. SBOMs come only from public open-source repositories.
