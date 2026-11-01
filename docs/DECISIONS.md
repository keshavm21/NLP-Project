# Decision log

Append-only. One line per decision: date, decision, reason, who. If a decision is reversed, add a new line that supersedes the old one (don't delete).

Status: **proposed** = default chosen when the docs were written; the team should confirm or change it in week 1. **settled** = confirmed.

| # | Date | Decision | Reason | Status | By |
|---|---|---|---|---|---|
| 1 | 2026-10-23 | Ecosystems limited to PyPI, npm, Maven (+ CPE for system libraries) | Keeps linking and matching tractable; best GHSA/OSV coverage | proposed | |
| 2 | 2026-10-23 | Temporal split: train ≤ 2024-12-31, dev 2025-01-01–2025-06-30, test 2025-07-01–snapshot | Realistic deployment setting + LLM contamination control | proposed | |
| 3 | 2026-10-23 | CVSS v3.1 base metrics only; v4.0 is a stretch goal | Most labels in the training window are v3.1 | proposed | |
| 4 | 2026-10-23 | Placeholder CWEs (`NVD-CWE-noinfo`, `NVD-CWE-Other`) excluded from training targets | They are not weakness types | proposed | |
| 5 | 2026-10-23 | NVD is the primary CWE/CVSS label; CNA labels kept for the agreement ceiling | Consistency; CNA-vs-NVD gives a human-agreement bound | proposed | |
| 6 | 2026-10-23 | Version ranges represented as `univers` `vers:` strings | Standard, ecosystem-aware comparison; no hand-written comparators | proposed | |
| 7 | 2026-10-23 | SBOMs generated with Syft in CycloneDX JSON; join on purl first, CPE second | Don't build SBOM tooling; purl is exact for packages | proposed | |
| 8 | 2026-10-23 | Default encoder: `microsoft/deberta-v3-base` | Strong baseline that fits one GPU | proposed | |
| 9 | 2026-10-23 | No proprietary API in the main pipeline; API LLMs used only as baselines | Project must not depend on a proprietary API | proposed | |
| 10 | 2026-10-23 | Gold sets are test-window only and never used for training or prompts | Clean evaluation | proposed | |
| 11 | 2026-10-23 | Shared starter code: schemas, module interfaces (`base.py`), pipeline glue, config/split helper, JSONL I/O, eval writer + metrics, CLI, CI | Lets all 5 work in parallel from day 1 | proposed | |
| 12 | 2026-10-23 | Core install excludes torch; ML libraries in the `ml` extra | CI and laptops stay light; only model owners install heavy deps | proposed | |
| 13 | 2026-10-25 | Annotation tool: doccano / Label Studio compatible JSONL export with local spreadsheet review | Zero cloud lock-in, reproducible in Git, direct Pydantic validation | settled | Ayush Khelwal |
| 14 | 2026-11-01 | Snapshot date set to 2026-10-25 in `configs/splits.yaml` | All downloads captured by this date; test window 2025-07-01 – 2026-10-25 | settled | Ayush Khelwal |
| 15 | 2026-11-01 | Silver label provenance: every silver span/link/label records its alignment method and source for downstream quality analysis | Enables silver-vs-gold precision measurement and label noise estimation | settled | Ayush Khelwal |

## To decide in week 1

- ~~Snapshot date for all downloads.~~ → **Decision #14** (2026-10-25)
- Exact training cutoff of each LLM baseline (needed for the `post_llm_cutoff` subset).
- Which ~40 open-source repos to use for SBOMs.
- ~~Annotation tool (Label Studio / doccano / spreadsheet).~~ → **Decision #13** (JSONL + doccano export)
- GPU access: where training runs (lab machine / Colab / Kaggle) and per-person budget.
- Postgres vs SQLite for the demo deployment.

