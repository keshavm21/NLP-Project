# P2 — Extraction & Normalization

**Owner:** Keshav Mishra  **Folder:** `src/vulntriage/extract/`  **Answers:** RQ1

## Your job in one sentence

Read an advisory and find *what* is affected and *which versions*, then turn phrases like "3.x before 3.1.1" into exact, machine-checkable ranges.

## Why it matters

If you get the product or version wrong, everything downstream is wrong: P3 links the wrong name, P5 alerts on the wrong projects. This is the core information-extraction problem of the project.

## Inputs → outputs

| You read | You produce |
|---|---|
| `Advisory.text` | `ExtractionResult`: spans (char offsets) + list of `AffectedItem` with a `vers:` range |
| Silver spans from P1 (training) | Trained tagger in `models/extract/` |
| Gold extraction set (testing only) | `results/extract/*.json` |

Span labels: `VENDOR`, `PRODUCT`, `VERSION_EXPR`, `FIXED_VERSION`.

## Tasks

### Week 1 — baseline
- [ ] Every extractor subclasses `Extractor` in `extract/base.py`.
- [ ] Regex baseline: product = capitalized/known-package tokens before "before/prior to/through…"; versions = version-number patterns. It will be bad; that's the point.
- [ ] Evaluate it on silver dev data through `eval/`; commit the results file.
- [ ] Collect ~50 real examples of version phrasing from the data and group them into families.

### Weeks 2–3 — main system
- [ ] **Span tagger:** fine-tune `deberta-v3-base` for BIO token classification on silver spans. Handle the tokenizer-offset mapping carefully so predicted spans map back to exact character offsets.
- [ ] **Version grammar** (`version_grammar.py`): deterministic parser from `VERSION_EXPR` text to ranges. Cover at least: before / prior to / through / up to and including / and earlier / X.x before Y / from A to B / A through B / lists / fixed in X / all versions. **One unit test per family.**
- [ ] Convert ranges with `univers` into `vers:` strings. If a phrase can't be parsed, output `None` — never guess.
- [ ] **Grouping:** when one advisory mentions several products with different ranges ("libfoo before 2.4.3 and libbar 1.x before 1.9"), attach each version span to the right product.

### Week 4 — comparison systems + integration
- [ ] **LLM extractor:** LoRA-fine-tune a small open model (~1.5–8B) to output the same JSON. Same evaluation.
- [ ] Large-LLM few-shot extractor as a baseline (prompts in `configs/extract/prompts/`).
- [ ] Hand predictions to P3 (mentions) and P5 (ranges) through `schemas.py`.

### Week 5 — experiments
- [ ] Ablation: no silver-label filtering (train including fuzzy alignments).
- [ ] Ablation: tagger without the grammar (let the LLM normalize instead).
- [ ] *(Stretch)* Domain shift: CVE descriptions → vendor bulletins.

### Week 6 — error analysis
- [ ] `results/extract/ERRORS.md`: 50 errors, categorized (unusual phrasing, multiple products, version lists, typos, label noise…).

## Experiments you own

| System | Purpose |
|---|---|
| Regex | Floor |
| DeBERTa tagger + grammar | Main system |
| LoRA small LLM → JSON | Generative alternative |
| Large LLM few-shot | Upper-ish baseline / RQ4 |

Report all of them broken down **by phrasing family** (`subset` field).

## Metrics
Span P/R/F1 (per label), range exact-match, range containment accuracy, fixed-version accuracy. See `docs/EVALUATION.md`.

## Definition of done
- Main system + 3 comparisons evaluated on the gold set, 3 seeds for the main model.
- Every grammar family has a passing unit test.
- 2 ablations done; error analysis written; RQ1 section of the report written.

## Viva questions to be ready for
- Why a tagger + grammar instead of just asking an LLM?
- How did you map subword tokens back to character spans?
- Which version phrasings are hardest and why?
- How does label noise in silver data affect your tagger?
- How do you attach a version range to the right product when there are several?
