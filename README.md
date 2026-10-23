# VulnTriage

**Turning free-text security advisories into a ranked "fix this first" list.**

Course project for DSL504 / DS504 – Natural Language Processing, IIT Bhilai (Jul–Nov 2026). Team of 5.

---

## The idea in 30 seconds

Every week, hundreds of software security warnings ("advisories") are published in plain English:

> *"A heap overflow in libfoo before 2.4.3, and 3.x before 3.1.1, allows remote attackers to execute arbitrary code."*

A computer can't act on that sentence directly. Someone has to work out *which software* it is about, *which versions* are broken, *how dangerous* it is, and *what version fixes it*. The official US database (NVD) used to do this by hand and fell months behind in 2024. Meanwhile every team is asking: **"Which of these warnings affect *our* software, and what do we fix first?"**

VulnTriage answers that question with NLP. It:

1. **reads** each advisory and pulls out the affected software, versions and fixed version;
2. **resolves names** — "Struts", "Apache Struts 2" and "struts2-core" are the same thing — to one official identifier;
3. **predicts** the weakness type (CWE) and severity (CVSS), with honest confidence scores;
4. **checks** the result against a project's dependency list (its SBOM);
5. **ranks** what's affected and shows a to-do list with the evidence highlighted:

```
payments-api uses libfoo 2.4.1
  → affected: versions before 2.4.3             [evidence: "before 2.4.3"]
  → weakness: CWE-787 out-of-bounds write (82% confident)
  → severity: network-exploitable, no login needed → Critical
  → known to be exploited in the wild (CISA KEV)
  → ACTION: upgrade libfoo to ≥ 2.4.3
```

New to security terms (CVE, CWE, CVSS, SBOM, purl…)? Read **[docs/GLOSSARY.md](docs/GLOSSARY.md)** first — it takes 10 minutes.

## Why this is an NLP project

The dashboard is just the window. The work is five language problems, each with its own model, baseline and metric:

| NLP problem | Example |
|---|---|
| Information extraction + normalization | "3.x prior to 3.1.1" → `>=3.0.0, <3.1.1` |
| Entity linking at scale (with "not found") | "Struts 2" → `pkg:maven/org.apache.struts/struts2-core` |
| Hierarchical, calibrated classification | text → CWE-787 (p = 0.82) |
| Multi-task structured prediction | text → `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Grounded generation | explanation that only states facts the system extracted |

And one headline experiment: **does our pipeline of specialized models beat a single large LLM doing the whole job** — on accuracy, calibration, speed and cost?

## Pipeline

```
advisory text
  → [P1] clean, merge duplicates across sources
  → [P2] extract product / version spans → normalize version ranges
  → [P3] link product mentions to identifiers (or "not found")
  → [P4] predict CWE + CVSS + exploitation signal, with calibrated confidence
  → [P5] match against SBOM → rank → explain → dashboard
```

Full design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Team and work division

Each member owns **one NLP component end to end**: its data, baseline, main model, ablation, evaluation, error analysis, and its section of the report and viva. Everyone also contributes to the gold-set annotation and the final report.

> **Fill in the "Member" column in the first team meeting**, then commit the change.

| Role | Member | Owns | Main deliverable | Research question | Detailed tasks |
|---|---|---|---|---|---|
| **P1 — Data & Benchmark** | Ayush Khelwal | `src/vulntriage/ingest/`, `data/gold/` | Downloaders for all sources, cleaned + deduplicated advisories, time-split train/dev/test, automatic ("silver") labels, hand-checked gold sets, annotation guidelines | Data quality (supports all RQs) | [P1 tasks](docs/tasks/P1_data_benchmark.md) |
| **P2 — Extraction & Normalization** | Keshav Mishra | `src/vulntriage/extract/` | Model that tags vendor / product / version / fixed-version spans + rules that turn version phrases into exact ranges; LLM extractor for comparison | RQ1 | [P2 tasks](docs/tasks/P2_extraction.md) |
| **P3 — Entity Linking** | Rishi Kharya | `src/vulntriage/linking/` | Search index over package names + CPEs, candidate retrieval, reranker, "not found" (NIL) detection | RQ2 | [P3 tasks](docs/tasks/P3_entity_linking.md) |
| **P4 — Weakness, Severity & Calibration** | Akshat Gupta | `src/vulntriage/classify/` | CWE classifier, CVSS predictor, exploitation-signal classifier, calibration, LLM baselines | RQ3 | [P4 tasks](docs/tasks/P4_classification.md) |
| **P5 — Matching, Ranking & End-to-End** | Shivam Singh | `src/vulntriage/match/`, `rank/`, `api/`, `web/`, `eval/replay.py` | SBOM matching, risk ranking, grounded explanations, API + dashboard, end-to-end replay evaluation, pipeline-vs-single-LLM comparison | RQ4, RQ5 | [P5 tasks](docs/tasks/P5_end_to_end.md) |

**Team members:** Shivam Singh · Keshav Mishra · Rishi Kharya · Akshat Gupta · Ayush Khelwal

### Shared responsibilities

| What | Who leads | Everyone does |
|---|---|---|
| `src/vulntriage/schemas.py` (data contracts between modules) | P5 | Review any change; never change it without a [DECISIONS](docs/DECISIONS.md) entry |
| `src/vulntriage/eval/` (metric code + result-file writer) | P4 | Report every result through it |
| Gold-set annotation | P1 | ~100 items each (≈ half a day) |
| Weekly sync + progress table | rotates | Update your row before the meeting |
| Final report | P1 compiles | Write your component's section (method, results, ablation, errors) |
| Demo + slides | P5 | Each person presents their component |

### How the five pieces fit together

```
          P1 data + labels
    ┌────────┼────────┬────────┐
    ▼        ▼        ▼        ▼
   P2 ────► P3       P4       P5
 (spans)  (links)  (CWE/CVSS) (match, rank, UI, end-to-end eval)
    └────────┴────────┴────────► P5
```

**Nobody waits for anybody.** Until the upstream component is ready, each person develops against the labels P1 provides (for example, P3 links the *correct* product spans from the labels instead of P2's predicted ones). We plug real components together in week 4.

---

## Research questions

- **RQ1** How accurately can affected products and version ranges be extracted and normalized from advisory text? *(P2)*
- **RQ2** How well can product mentions be linked to a very large identifier space, including "not found"? *(P3)*
- **RQ3** Can CWE and CVSS be predicted from text accurately *and* with well-calibrated confidence? *(P4)*
- **RQ4** Does the modular pipeline beat a single LLM on accuracy, calibration, latency and cost? *(P5, using everyone's metrics)*
- **RQ5** On real projects' dependency lists, how precise and complete are the alerts? *(P5)*

## Timeline

Week numbers count from project start. If we have fewer weeks, follow the **minimum track** in [docs/WORK_PLAN.md](docs/WORK_PLAN.md).

| Week | Goal | Everyone has… |
|---|---|---|
| 1 | Setup + baselines | read the docs, set up the env, a simple baseline running, first results file committed |
| 2–3 | Main models | main model trained, dev-set numbers committed |
| 4 | Integration | gold sets annotated; full pipeline runs end to end on dev |
| 5 | Experiments | ablations done, test numbers frozen, pipeline-vs-LLM comparison done |
| 6 | Analysis + demo | error analysis written, end-to-end replay results, dashboard working |
| 7 | Wrap-up | report, slides, demo rehearsed |

Details, dependencies and checkpoints: [docs/WORK_PLAN.md](docs/WORK_PLAN.md).

---

## Repository layout

```
vulntriage/
├── README.md                ← you are here
├── CONTRIBUTING.md          ← git workflow, code style, how to report results
├── docs/
│   ├── GLOSSARY.md          ← security + project terms, start here
│   ├── PROJECT.md           ← problem, goals, scope, definition of done
│   ├── ARCHITECTURE.md      ← modules, data flow, data contracts
│   ├── DATA.md              ← every data source, splits, labels
│   ├── EVALUATION.md        ← metrics, baselines, ablations, end-to-end protocol
│   ├── WORK_PLAN.md         ← timeline, dependencies, checkpoints
│   ├── DECISIONS.md         ← log of decisions we've made
│   └── tasks/               ← one detailed task file per member (P1–P5)
├── configs/                 ← YAML configs (split dates, model settings)
├── src/vulntriage/
│   ├── schemas.py           ← shared data contracts
│   ├── config.py  jsonl.py  pipeline.py  cli.py
│   ├── ingest/   extract/   linking/   classify/   ← each has base.py (interface)
│   ├── match/    rank/      api/       eval/       utils/
├── web/                     ← dashboard
├── tests/                   ← mirrors src/ layout
├── results/                 ← metric JSON files (committed)
├── data/                    ← downloaded + processed data (NOT committed)
└── models/                  ← checkpoints (NOT committed)
```

## Getting started

```bash
git clone https://github.com/<org-or-user>/vulntriage.git
cd vulntriage
python3.11 -m venv .venv && source .venv/bin/activate
make setup                    # core + dev tools (light, no torch)
make setup-ml                 # add ML libraries (P2, P3, P4; P5 for the LLM baseline)
cp .env.example .env          # then add your free NVD API key
make test                     # should pass on a fresh clone
make status                   # which pipeline steps exist yet, and who owns each
```

## Shared starter code (already written)

Everything everyone depends on exists from day 1, so the five of us can work in parallel without waiting for each other:

| File | What it gives you |
|---|---|
| `src/vulntriage/schemas.py` | The data contracts: `Advisory`, `Span`, `AffectedItem`, `ExtractionResult`, `LinkedProduct`, `Prediction`, `SBOM`, `Match`, `QueueItem` |
| `src/vulntriage/<module>/base.py` | The interface you implement: `Source` (P1), `Extractor` (P2), `Linker` (P3), `Classifier` (P4), `Matcher` + `Ranker` (P5) |
| `src/vulntriage/pipeline.py` | Glue that runs any combination of implementations end to end |
| `src/vulntriage/config.py` | Repo paths, `.env` secrets, YAML loading, and the **only** train/dev/test split rule |
| `src/vulntriage/jsonl.py` | Read/write data files of schema objects |
| `src/vulntriage/eval/results.py` | `write_result(...)` — the one way to save a reported number |
| `src/vulntriage/eval/metrics.py` | Span P/R/F1, accuracy, macro-F1, top-k, ECE, MAE, Recall@k, NIL P/R/F1, NDCG |
| `src/vulntriage/utils/` | `set_seed`, `get_logger` |
| `src/vulntriage/cli.py` + `Makefile` | `make data`, `make train-cwe`, … each points to the module its owner will create |
| `tests/shared/` | Tests for all of the above, incl. a full pipeline run with fake components — **read `test_pipeline.py` to see how your piece plugs in** |
| `.github/workflows/ci.yml` | Lint + tests on every pull request |

To add your step: create the module named in `make status` (e.g. `src/vulntriage/classify/train_cwe.py`) with a `main(argv)` function. `make train-cwe` then runs it.

Common commands (added to the `Makefile` as we go):

| Command | What it does |
|---|---|
| `make data` / `make benchmark` | Download sources / build splits + silver labels |
| `make train-<component>` | Train `extract`, `link`, `cwe`, `cvss` or `exploit` |
| `make eval-<component>` | Evaluate and write `results/<component>/<run_id>.json` |
| `make eval-e2e` | Full replay over the test window |
| `make serve` | Run API + dashboard locally |
| `make test` / `make lint` / `make format` | Tests / style checks / auto-format |
| `make status` | Which steps are implemented, and who owns each |

## Ground rules (read before your first commit)

1. **Never train on test data.** The train/dev/test dates in `configs/splits.yaml` are the only boundaries. Nothing published after the training cutoff may be used for training, tuning or building indexes.
2. **Gold sets are for testing only** — never for training or as LLM prompt examples.
3. **Every component has a simple baseline** before the fancy model.
4. **Every reported number comes from a results file** written by `src/vulntriage/eval/`. No numbers copied from a notebook.
5. **No data or model weights in git.** Everything is rebuildable with `make data && make benchmark`.
6. **Don't change `schemas.py` alone.** Discuss, then log it in `docs/DECISIONS.md`.
7. **Defensive only.** No exploit code is downloaded, written or generated.

Full workflow: [CONTRIBUTING.md](CONTRIBUTING.md).

## Data sources

All public and free: NVD, CVE JSON 5 records, CISA Vulnrichment, GitHub Advisory Database, OSV, CPE dictionary, CWE catalog, CISA KEV, FIRST EPSS, CTIBench. Details in [docs/DATA.md](docs/DATA.md).
