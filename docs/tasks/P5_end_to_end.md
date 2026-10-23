# P5 — Matching, Ranking & End-to-End

**Owner:** Shivam Singh  **Folder:** `src/vulntriage/match/`, `rank/`, `api/`, `web/`, `eval/replay.py`, lead on `schemas.py`  **Answers:** RQ4, RQ5

## Your job in one sentence

Turn everyone's outputs into the final product — match advisories to real projects' dependencies, rank them, explain them in grounded language, show them in a dashboard — and run the two headline evaluations: end-to-end replay and pipeline vs single LLM.

## Why it matters

This is where "NLP predictions" become "an action a person can take", and where we prove the whole system works. Your two experiments are the headline results of the report.

## Inputs → outputs

| You read | You produce |
|---|---|
| `ExtractionResult` (P2), `LinkedProduct` (P3), `Prediction` (P4) | `Match`, `QueueItem` |
| SBOMs generated with Syft from ~40 open-source repos | `data/sboms/` + `manifest.json` (repo + commit) |
| KEV, EPSS (from P1) | Ranked queue, explanations, dashboard |
| GHSA/OSV structured ranges (ground truth, never shown to the system) | `results/e2e/*.json`, `results/rq4/*.json` |

## Tasks

### Week 1 — contracts + skeleton
- [x] Starter `schemas.py`, `pipeline.py`, module interfaces (`base.py`), `pyproject.toml`, `Makefile`, CI — already in the repo.
- [ ] Own `schemas.py` from here: walk the team through it in the first meeting, collect change requests, **freeze it by end of week 1**.
- [ ] Pick ~40 open-source repos across PyPI/npm/Maven; generate CycloneDX SBOMs with Syft; record repo + commit.

### Weeks 2–3 — matching + ranking (using gold/silver inputs)
- [ ] `match/`: parse SBOMs, join on purl (then CPE), version containment via `univers`. Unit tests with hand-made SBOMs.
- [ ] `rank/score.py`: heuristic risk score = CVSS × KEV × EPSS × asset criticality × confidence. Make weights configurable.
- [ ] `rank/routing.py`: below a confidence threshold → `needs_review`.
- [ ] `eval/replay.py`: replay test-window advisories in publication order; system sees **text only**; compare with ground truth from GHSA/OSV ranges.

### Week 4 — explanations, API, integration
- [ ] `rank/explain.py`: short analyst note generated **only** from extracted fields (template first; small LLM second).
- [ ] `rank/verify.py`: drop any sentence not supported by a field or evidence span; measure verifier precision/recall on 50 manually judged notes.
- [ ] FastAPI: `POST /advisories/analyze`, `GET /queue?sbom=…`, `GET /items/{id}`, `POST /items/{id}/feedback`.
- [ ] Swap gold inputs for P2/P3/P4's real models → full pipeline on dev.

### Week 5 — headline experiments
- [ ] **RQ4 single-LLM system:** one prompt that reads the advisory and outputs extraction + identifier + CWE + CVSS in our schema. Run it on the same test items; collect every component metric, ECE, latency and cost per 1,000 advisories. Report the post-cutoff subset.
- [ ] **RQ5 replay:** alert precision/recall, alerts per true issue, NDCG@10/25 against the KEV/EPSS/CVSS reference, day-0 agreement with NVD's later labels, review-lane error rates.
- [ ] Ablation: ranking without exploitation signals.

### Week 6 — dashboard + demo
- [ ] `web/`: queue view, item view with highlighted evidence spans and confidence, "paste an advisory" box, replay mode.
- [ ] *(Stretch)* Learned ranker; blind rating study (5–8 people, 30 items, ours vs single-LLM).
- [ ] Demo script: last week's advisories + 3 well-known repos → ~600 advisories collapse to a ranked dozen → click through one → paste a live advisory.

## Experiments you own

| Experiment | Purpose |
|---|---|
| Replay over test window, ~40 SBOMs | RQ5: does the whole system work? |
| Modular pipeline vs single LLM | RQ4: is the modular design worth it? |
| Gold-input vs real-input pipeline | Error propagation end to end |
| Heuristic vs learned ranking *(stretch)* | Ranking quality |
| Explanation verifier | Faithfulness |

## Definition of done
- `make eval-e2e` runs the full replay with one command.
- RQ4 and RQ5 results committed; dashboard demo works offline.
- RQ4 + RQ5 sections of the report written; demo rehearsed.

## Viva questions to be ready for
- How do you know an alert is correct without the system seeing the structured data?
- Why does the modular pipeline win (or lose) against one LLM?
- How do errors in extraction/linking propagate to alerts?
- How do you make sure explanations don't hallucinate?
- How was the risk score designed, and how would you validate it?
