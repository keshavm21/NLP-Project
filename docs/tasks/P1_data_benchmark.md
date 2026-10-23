# P1 — Data & Benchmark

**Owner:** Ayush Khelwal  **Folder:** `src/vulntriage/ingest/`, `data/gold/`  **Supports:** every RQ

## Your job in one sentence

Build the dataset everyone else trains and tests on: download every source, turn it into one clean format, split it by date, create automatic training labels, and run the hand-checked gold sets.

## Why it matters

Every other member is blocked until you ship a first version of the data. A rough version in week 1 beats a perfect one in week 3. The quality of your silver labels decides how good P2 and P3's models can be.

## Inputs → outputs

| You read | You produce |
|---|---|
| NVD, CVE JSON 5, Vulnrichment, GitHub Advisory DB, OSV, CPE dictionary, CWE catalog, KEV, EPSS (see `docs/DATA.md`) | `data/processed/{train,dev,test}.jsonl` — one `Advisory` per line |
| | `data/processed/silver/{spans,links,cwe,cvss,exploit}.jsonl` |
| | `data/gold/{extraction,linking,bulletins}.jsonl` |
| | `docs/annotation_guidelines.md` |
| | `results/ingest/*.json` — dataset stats + alignment coverage |

## Tasks

### Week 1 — ship benchmark v0 (highest priority in the whole project)
- [ ] One downloader per source in `ingest/sources/<name>.py`, each a subclass of `Source` in `ingest/base.py`. Wire them into `ingest/download.py` (`make data`). Each writes to `data/raw/<name>/`, skips files already downloaded, and logs the download date.
- [ ] Get a free NVD API key; read it from `.env` (`NVD_API_KEY`). Respect rate limits.
- [ ] `normalize.py`: convert every source into the `Advisory` schema (`docs/ARCHITECTURE.md`).
- [ ] `benchmark.py` (`make benchmark`): assign train/dev/test with `load_splits().assign(published)` from `config.py` — never re-implement the date rule.
- [ ] **Alignment check (critical):** on 1,000 GHSA/OSV advisories, try to find the structured package name and version boundaries inside the description text. Report what % align by exact / normalized / fuzzy match. Share the number with the team the same day.
- [ ] Commit `results/ingest/stats_v0.json` (counts per source, per split, per ecosystem).

### Weeks 2–3 — labels
- [ ] **Silver spans** for P2: for each aligned advisory, character offsets + label (`VENDOR`, `PRODUCT`, `VERSION_EXPR`, `FIXED_VERSION`) + alignment method. Keep only advisories where *every* structured product is found.
- [ ] **Silver links** for P3: (mention, context, identifier) pairs; alias pairs from records that have both a purl and a CPE — train window only.
- [ ] **CWE / CVSS labels** for P4 from NVD (primary) and CNA/Vulnrichment (kept separately for the agreement study). Drop placeholder CWEs; count how many.
- [ ] **Exploitation labels** for P4 from KEV + text cues (weak labels — document how).
- [ ] Manually check 100 random silver alignments → report silver-label precision.
- [ ] `dedup.py`: merge records for the same vulnerability across sources (shared CVE/GHSA aliases first; text similarity only for records without IDs).

### Week 3–4 — gold sets (you lead, everyone annotates)
- [ ] Write `docs/annotation_guidelines.md` with 10+ worked examples, especially tricky version phrases.
- [ ] Choose a tool (Label Studio / doccano / spreadsheet) — log it in DECISIONS.
- [ ] Sample test-window items: 500 for extraction gold (200 on the minimum track), 300 mentions for linking gold; split annotation across all 5 members.
- [ ] Double-annotate 100 items; compute agreement (span F1 between annotators, Cohen's κ for categorical fields). Resolve disagreements.
- [ ] *(Stretch)* Collect ~150 vendor bulletins / mailing-list posts for the domain-shift test.

### Weeks 5–7
- [ ] Final dataset statistics table and silver-vs-gold quality analysis for the report.
- [ ] Compile the final report (each member writes their own section).

## Experiments you own

| Experiment | Question |
|---|---|
| Alignment coverage by method and source | How much usable silver data do we get? |
| Silver precision on 100 manual checks | How noisy is the training data? |
| Inter-annotator agreement | How reliable is our gold set? |
| Label shift across splits (CWE / CVSS / ecosystem distribution by year) | Is the test set harder or different? |

## Definition of done
- `make data && make benchmark` rebuilds everything from scratch on a fresh machine.
- Gold sets + guidelines committed; agreement reported.
- Stats and silver-quality numbers in `results/ingest/`.
- Data section of the report written.

## Viva questions to be ready for
- Why split by date and not randomly?
- How did you create silver labels, and how noisy are they?
- What did you do when NVD and the CNA disagreed?
- How did you prevent test data from leaking into training?
- What is your inter-annotator agreement and what does it mean?
