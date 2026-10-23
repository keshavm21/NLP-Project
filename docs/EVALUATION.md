# Evaluation

All numbers in the report come from `results/`. Every run writes one JSON file through `src/vulntriage/eval/`.

## Result-file format

`results/<component>/<run_id>.json`

```json
{
  "run_id": "cwe_deberta_hier_2026-11-02_s42",
  "component": "cwe",
  "system": "deberta-v3-base + hierarchical loss + label descriptions",
  "baseline_of": null,
  "split": "test",
  "subset": "all",
  "n": 4123,
  "metrics": {"accuracy": 0.0, "macro_f1": 0.0, "hier_f1": 0.0, "ece": 0.0},
  "seed": 42,
  "git_commit": "abc1234",
  "config": "configs/cwe/hier.yaml",
  "data_snapshot": "2026-10-25",
  "runtime_sec": 0.0,
  "cost_usd": 0.0,
  "notes": ""
}
```

Use `subset` for breakdowns (e.g., `phrasing=before_x`, `cwe=tail`, `post_llm_cutoff`). Run each main system with 3 seeds and report mean ± std.

## Component metrics

### Extraction + normalization (P2)
| Metric | Definition |
|---|---|
| Span P/R/F1 | Exact-match spans, per label and micro-averaged |
| Range exact-match | Predicted `vers:` range equals gold range |
| Range containment accuracy | For sampled versions, predicted range and gold range agree on "affected?" |
| Fixed-version accuracy | Exact match |

Breakdown by phrasing family (see `extract/version_grammar.py`).

**Systems:** regex baseline → fine-tuned DeBERTa tagger + grammar → LoRA small LLM (JSON) → large LLM few-shot.

### Entity linking (P3)
| Metric | Definition |
|---|---|
| Acc@1 | Top candidate is correct (non-NIL gold) |
| Recall@10 | Correct identifier in top 10 candidates |
| NIL P/R/F1 | NIL detection quality |
| Overall accuracy | Including NIL decisions |

**Systems:** exact/fuzzy string match → BM25 → bi-encoder → bi-encoder + cross-encoder. Sweep the NIL threshold on dev.

### CWE (P4)
| Metric | Definition |
|---|---|
| Accuracy / top-3 accuracy | |
| Macro-F1 | Over classes with ≥ N test examples |
| Hierarchical F1 | Credit for ancestors in the CWE tree |
| Head vs tail | Split classes by training frequency |
| Conformal coverage + avg set size | At target coverage 90% |
| ECE | Expected calibration error, before vs after temperature scaling |

**Systems:** TF-IDF + logistic regression → fine-tuned encoder → + hierarchy-aware loss → + label descriptions → LLM zero/few-shot (compare with CTIBench numbers).

### CVSS (P4)
| Metric | Definition |
|---|---|
| Per-metric accuracy / macro-F1 | For each of AV, AC, PR, UI, S, C, I, A |
| Full-vector exact match | |
| Base-score MAE | Score computed from predicted vector |
| Severity-band accuracy | None/Low/Medium/High/Critical |
| ECE per metric | |
| **Human ceiling** | Same metrics computed between CNA and NVD vectors on CVEs that have both |

**Systems:** independent heads vs multi-task head; encoder vs LLM.

### Exploitation signal (P4)
AUROC, AUPRC (positives are rare), precision at fixed recall.

### Grounded explanation (P5)
- Share of generated sentences supported by an extracted field or evidence span (automatic check + manual check on 50).
- Verifier precision/recall against manual judgments.

## RQ4: modular pipeline vs single LLM

Same test advisories, same output schema. The single-LLM system receives the advisory text and must output extraction + linking (free-text identifier) + CWE + CVSS in one call.

Report side by side: every component metric above, ECE, latency per advisory, cost per 1,000 advisories, and results restricted to `post_llm_cutoff` items.

## Ablations (minimum set)

| Ablation | Component |
|---|---|
| No silver-label filtering (keep fuzzy alignments) | Extraction |
| Tagger without the version grammar (LLM-only normalization) | Extraction |
| No cross-encoder reranker | Linking |
| No alias mining | Linking |
| No hierarchy loss / no label descriptions | CWE |
| Independent vs multi-task CVSS | CVSS |
| No calibration | CWE, CVSS, routing |
| Ranking without exploitation signals (KEV/EPSS/text) | Ranking |
| Domain shift: CVE descriptions → vendor bulletins | Extraction, linking |

## End-to-end evaluation (P5, uses everyone's components)

**Replay protocol.**
1. Take ~40 SBOMs (Syft-generated from real open-source repos; record repo + commit).
2. Replay test-window advisories in publication order. The system only sees advisory **text** (no structured fields).
3. Ground truth: (component, advisory) pairs derived from GHSA/OSV structured ranges, which the system never sees.

**Metrics.**
| Metric | Meaning |
|---|---|
| Alert precision / recall | Over (component, advisory) pairs |
| Alerts per true issue | Noise level |
| NDCG@10 / @25 of the queue | Against a reference priority from KEV status + EPSS + CVSS |
| Day-0 agreement | For CVEs NVD enriched late: how often our day-0 CWE/CVSS/affected output matches NVD's eventual labels |
| Review-lane rate | Share of items routed to human review, and error rate inside vs outside the lane |

**Small rating study (optional, if time).** 5–8 participants judge 30 queue items (usefulness of explanation, correctness of recommended action) for our system vs single-LLM output, blind.

## Error analysis (required per component)

Each owner writes `results/<component>/ERRORS.md`: 50 sampled errors, categorized (e.g., unusual phrasing, multiple products in one sentence, ambiguous product name, label noise), with counts and 2–3 examples per category.
