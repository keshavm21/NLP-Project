# Work plan

How the five workstreams fit together in time. Per-person checklists are in `docs/tasks/`.

## Dependencies

| Who needs | What | From | By | Stand-in until then |
|---|---|---|---|---|
| Everyone | `eval/` result writer + metrics | P4 | ✅ starter in repo | P4 extends it |
| Everyone | `schemas.py` + interfaces | P5 | ✅ starter in repo; frozen end week 1 | — |
| P2, P3, P4 | Benchmark v0 (splits + raw labels) | P1 | end week 1 | — (ship early, even rough) |
| P2 | Silver spans | P1 | week 2 | Hand-label 200 examples |
| P3 | Product mentions | P2 | week 4 | Gold/silver product spans |
| P5 | Ranges + identifiers | P2, P3 | week 4 | GHSA/OSV structured fields |
| P5 | CWE / CVSS / exploitation | P4 | week 4 | NVD labels |
| Everyone | Gold sets | P1 (all annotate) | week 4 | Silver dev set |

Of the three week-1 blockers, two (shared code and schemas) are already done; only P1's benchmark v0 remains. Everything else has a stand-in, so nobody waits.

## Timeline and checkpoints

Fill in real dates at the first meeting: Week 1 starts on `____`, final submission on `____`.

| Week | P1 Data | P2 Extraction | P3 Linking | P4 Classification | P5 End-to-end | Checkpoint (all) |
|---|---|---|---|---|---|---|
| 1 | Downloaders, splits, alignment check, benchmark v0 | Regex baseline, phrasing families | Candidate table, fuzzy + BM25 baselines | Extend `eval/`, TF-IDF baselines | Freeze `schemas.py`, SBOMs | **Every component has a baseline result file** |
| 2 | Silver spans, links, labels | DeBERTa tagger | Bi-encoder + FAISS | DeBERTa CWE | SBOM matching | |
| 3 | Silver precision check, dedup, annotation guidelines | Version grammar + tests | Cross-encoder, alias mining | CVSS multi-task, exploitation | Ranking, replay harness | **Every main model has dev numbers** |
| 4 | Gold annotation (all help) | LLM extractors | NIL, propagation | Calibration, LLM baselines, ceiling | Explanations, verifier, API, integration | **Full pipeline runs end to end on dev** |
| 5 | Label-shift analysis | Ablations | Ablations | Ablations | RQ4 + RQ5 experiments | **Test numbers frozen — no more tuning** |
| 6 | Stats tables | Error analysis | Error analysis | Error analysis | Dashboard, demo script | **Report draft complete** |
| 7 | Compile report | Report section | Report section | Report section | Slides, demo rehearsal | **Submit** |

## Minimum track (if we have ~4–5 weeks)

Keep: one baseline + one main model + one ablation per component; RQ4 comparison; end-to-end replay; dashboard.

Cut: vendor-bulletin domain-shift set, learned ranker, rating study, security-domain encoder, extraction gold set reduced from 500 to 200, LLM extractor reduced to one (either LoRA or few-shot).

Compressed schedule: weeks 1–2 merged into week 1 (baselines + benchmark v0), week 2 = main models, week 3 = gold sets + integration, week 4 = experiments + error analysis, week 5 = report + demo.

## Weekly sync (30 min)

Before the meeting, each person updates their row:

| Member | Done this week | Results files added | Blocked on | Next week |
|---|---|---|---|---|
| P1 | | | | |
| P2 | | | | |
| P3 | | | | |
| P4 | | | | |
| P5 | | | | |

Keep this table in a GitHub issue titled `Week N sync` (one issue per week) so we have a history.

## Risks and what we do about them

| Risk | Early sign | Response |
|---|---|---|
| Silver alignment coverage is poor | Week-1 check < ~50% clean | Restrict to GHSA/OSV advisories (cleanest); hand-label 200 more |
| GPU time is short | Training runs > 6 h | Use `deberta-v3-small`, fewer epochs, shared Kaggle/Colab quotas; log in DECISIONS |
| Integration breaks late | Schema arguments in week 4 | Schemas frozen at end of week 1; changes need a DECISIONS entry |
| NVD API rate limits slow downloads | Downloads take days | Use the API key; prefer bulk git repos (cvelistV5, advisory-database) |
| Scope creep into SBOM tooling or UI | P5 behind on experiments | UI is minimal until week 6; Syft handles SBOMs |
| Someone falls behind | Missed checkpoint | Minimum track for that component; others help with annotation, not their model |
