# P3 — Entity Linking

**Owner:** Rishi Kharya  **Folder:** `src/vulntriage/linking/`  **Answers:** RQ2

## Your job in one sentence

Take a product mention like "Struts 2" and find its one official identifier (a purl like `pkg:maven/org.apache.struts/struts2-core`, or a CPE) out of over a million candidates — or say "not found" (NIL).

## Why it matters

The SBOM lists exact package identifiers. Unless the advisory's product mention is linked to the same identifier, P5 can't tell whether a project is affected. Names in advisories are messy: abbreviations, marketing names, vendor prefixes, plugin names.

## Inputs → outputs

| You read | You produce |
|---|---|
| Product mention + its sentence (from P2, or gold/silver spans until P2 is ready) | `LinkedProduct`: identifier or `None`, score, top-k candidates |
| CPE dictionary + PyPI/npm/Maven package names (from P1) | Search index in `models/linking/` |
| Silver link pairs + aliases (train window only) | `results/linking/*.json` |

## Tasks

### Week 1 — index + baseline
- [ ] Every linker subclasses `Linker` in `linking/base.py`.
- [ ] Build the candidate table: one row per identifier with name, vendor/namespace, ecosystem, description (if available), known aliases.
- [ ] Baseline 1: exact + fuzzy string match (e.g., `rapidfuzz`).
- [ ] Baseline 2: BM25 over names + aliases.
- [ ] Commit baseline results (Acc@1, Recall@10) on silver dev.

### Weeks 2–3 — neural retrieval + reranking
- [ ] **Bi-encoder:** embed mentions (with context) and candidates; FAISS index; fine-tune on silver pairs with in-batch + hard negatives (hard negatives = top BM25 results that are wrong).
- [ ] **Candidate generation:** union of BM25 top-k and bi-encoder top-k. Report Recall@k for k = 1, 10, 50, 100 — reranking can't fix what retrieval missed.
- [ ] **Cross-encoder reranker:** fine-tune on (mention + sentence, candidate) pairs.
- [ ] **Alias mining:** pairs from records with both a purl and a CPE, train window only.

### Week 4 — NIL + integration
- [ ] **NIL detection:** threshold on reranker score (tuned on dev) vs a small classifier. Create NIL test cases by removing some gold identifiers from the index.
- [ ] Use ecosystem hints from the text ("npm package", "Python library") as a feature or filter.
- [ ] Plug in P2's real predicted mentions; measure the drop vs gold mentions (error propagation).

### Week 5 — experiments
- [ ] Ablations: no reranker, no alias mining, no context sentence, no hard negatives.
- [ ] NIL threshold sweep curve.

### Week 6 — error analysis
- [ ] `results/linking/ERRORS.md`: 50 errors (ambiguous names, forks, plugins vs core product, vendor confusion, missing aliases…).

## Experiments you own

| System | Purpose |
|---|---|
| Exact/fuzzy match | Floor |
| BM25 | Classic IR baseline |
| Bi-encoder | Dense retrieval |
| Bi-encoder + cross-encoder | Main system |
| + NIL detection | Full linker |
| Gold mentions vs P2 predicted mentions | Error propagation |

## Metrics
Acc@1, Recall@10, NIL P/R/F1, overall accuracy. See `docs/EVALUATION.md`.

## Definition of done
- Index builds with one Makefile command.
- Main system + baselines + NIL evaluated on the gold linking set, 3 seeds.
- 2+ ablations, propagation study, error analysis, RQ2 section written.

## Viva questions to be ready for
- Why two stages (retrieve, then rerank)?
- What are hard negatives and why do they help?
- How do you decide something is NIL?
- How did you stop alias data from the test period leaking into the index?
- How much do upstream extraction errors hurt linking?
