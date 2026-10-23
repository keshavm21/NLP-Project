# P4 — Weakness, Severity & Calibration

**Owner:** Akshat Gupta  **Folder:** `src/vulntriage/classify/`, lead on `src/vulntriage/eval/`  **Answers:** RQ3

## Your job in one sentence

From the advisory text, predict *what kind* of bug it is (CWE), *how severe* it is (the 8 CVSS metrics), and whether it's being *exploited* — and make the confidence scores trustworthy.

## Why it matters

Severity and exploitation decide the order of the to-do list. Calibrated confidence decides which items go to a human for review. You also lead the shared evaluation code that every member uses.

## Inputs → outputs

| You read | You produce |
|---|---|
| `Advisory.text` | `Prediction`: ranked CWEs with probabilities, conformal CWE set, CVSS vector + per-metric probabilities, base score, exploitation probability |
| CWE / CVSS / exploitation labels from P1 | Models in `models/classify/` |
| CWE catalog (names, descriptions, tree) | `results/{cwe,cvss,exploit}/*.json` |

## Tasks

### Week 1 — shared eval + baselines
- [x] `src/vulntriage/eval/` starter exists: `write_result` + common metrics (span P/R/F1, macro-F1, top-k, ECE, MAE, Recall@k, NIL, NDCG), with tests.
- [ ] Own it from here: review it, add what's missing (hierarchical CWE F1, AUROC/AUPRC, reliability-diagram plotting), help teammates use it.
- [ ] Every predictor subclasses `Classifier` in `classify/base.py`.
- [ ] TF-IDF + logistic regression baselines for CWE and each CVSS metric.
- [ ] Majority-class baseline per CVSS metric (some metrics are very skewed — know your floor).

### Weeks 2–3 — main models
- [ ] **CWE classifier:** fine-tuned DeBERTa. Then add (a) a hierarchy-aware loss using the CWE tree, (b) CWE label descriptions as extra signal for rare classes.
- [ ] **CVSS model:** one shared encoder with 8 classification heads (multi-task) vs 8 separate models. Compute the base score from the predicted vector using the official v3.1 formula (write a tested function).
- [ ] **Exploitation classifier:** text + reference-title cues; weak labels from P1. Report AUPRC (positives are rare).

### Week 4 — calibration + LLM baselines
- [ ] Temperature scaling on dev; ECE before/after; reliability diagrams.
- [ ] Conformal prediction sets for CWE at 90% target coverage; report actual coverage and average set size.
- [ ] LLM baselines (zero/few-shot) for CWE and CVSS; compare with published CTIBench numbers. Log each LLM's training cutoff and report the post-cutoff subset.
- [ ] **Human ceiling:** compute agreement between CNA and NVD vectors on CVEs that have both.

### Week 5 — experiments
- [ ] Ablations: no hierarchy loss, no label descriptions, multi-task vs independent, no calibration.
- [ ] Head vs tail CWE breakdown.
- [ ] *(Stretch)* Security-domain encoder vs general encoder (domain adaptation).

### Week 6 — error analysis
- [ ] `results/{cwe,cvss}/ERRORS.md`: confusions between sibling CWEs, vague descriptions, label noise, metrics the text simply doesn't mention.

## Experiments you own

| System | Task |
|---|---|
| Majority / TF-IDF+LR | Floors |
| DeBERTa (+ hierarchy, + descriptions) | CWE main |
| Multi-task vs independent heads | CVSS main |
| LLM zero/few-shot | Baselines / RQ4 |
| CNA vs NVD agreement | Human ceiling |
| Temperature scaling, conformal sets | Calibration |

## Metrics
CWE: accuracy, top-3, macro-F1, hierarchical F1, ECE, conformal coverage/set size. CVSS: per-metric F1, vector exact match, base-score MAE, severity-band accuracy, ECE. Exploitation: AUROC, AUPRC.

## Definition of done
- `eval/` used by all members.
- CWE, CVSS, exploitation models + baselines on test, 3 seeds; calibration done; human ceiling reported.
- 3+ ablations, error analyses, RQ3 section written.

## Viva questions to be ready for
- Why predict the vector instead of the score?
- What is calibration and why does it matter for routing?
- How does the hierarchy loss help rare CWEs?
- What does conformal prediction guarantee, and under what assumption?
- How close are you to the CNA-vs-NVD human agreement?
