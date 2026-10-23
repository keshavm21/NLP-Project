# Data

All core data is public and free. Raw files go to `data/raw/<source>/`, processed splits to `data/processed/`, hand-labeled gold sets to `data/gold/`. None of this is committed; `make data && make benchmark` rebuilds everything.

> Endpoints and repo layouts change. Before writing a fetcher, check the source's current docs and record the exact URL/version used in `docs/DECISIONS.md`.

## Sources

| Source | What we use | Used for | Access |
|---|---|---|---|
| **NVD** (CVE API 2.0) | Description, analyst CPE configurations (with version ranges), CWE, CVSS v3.1 vectors, published/modified dates | Labels for extraction, linking, CWE, CVSS | REST API. Rate-limited; request a free NVD API key and put it in `.env` as `NVD_API_KEY` |
| **CVE JSON 5 records** (`CVEProject/cvelistV5` on GitHub) | CNA-supplied `affected` blocks (vendor, product, versions), CNA CVSS/CWE | Second label source; CNA-vs-NVD agreement ceiling | Git clone / release zips |
| **CISA Vulnrichment** (`cisagov/vulnrichment`) | ADP-added CWE/CVSS/SSVC for CVEs | Extra labels, especially for the NVD backlog period | Git clone |
| **GitHub Advisory Database** (`github/advisory-database`) | Reviewed advisories in OSV format: package (purl), ecosystem, affected ranges, fixed versions, CWE, aliases | Best distant supervision for package-level extraction + linking | Git clone |
| **OSV** | Same format across PyPI/npm/Maven, with aliases to CVE/GHSA | Distant supervision; end-to-end ground truth | Bulk per-ecosystem zip downloads |
| **CPE dictionary** (NVD CPE API 2.0) | CPE names + titles | Linking candidate space | REST API |
| **CWE catalog** (MITRE, XML) | IDs, names, descriptions, parent/child relations, views | CWE hierarchy + label descriptions | XML download |
| **CISA KEV** | Known-exploited CVE list with dates | Exploitation feature + ranking ground truth | JSON feed |
| **FIRST EPSS** | Daily exploitation-probability scores | Ranking feature + ranking evaluation | CSV / API |
| **CTIBench** | CVE→CWE mapping and CVSS-prediction tasks with LLM results | Published LLM baselines for comparison | Hugging Face |
| **Vendor bulletins / mailing lists** | Free-text advisories without structured fields | Domain-shift test set | Small manual collection (~150 items) |
| **SBOMs** | CycloneDX JSON generated with **Syft** from ~40 real open-source repos (PyPI/npm/Maven) | End-to-end evaluation | Generated locally; record repo + commit hash |

## Splits (`configs/splits.yaml`)

Split by the advisory's **first `published` date**:

| Split | Window | Purpose |
|---|---|---|
| train | ≤ 2024-12-31 | Training, building indexes and vocabularies |
| dev | 2025-01-01 – 2025-06-30 | Model selection, threshold tuning, calibration |
| test | 2025-07-01 – snapshot date | All reported numbers |

Rules:
- The candidate index for linking may include identifiers that exist by the snapshot date (identifiers are not labels), but **alias pairs mined from test-window records must not be used**.
- For every LLM baseline, record its training cutoff in DECISIONS.md and report its results on test items published **after** that cutoff (contamination control).
- Record the snapshot date and the git commit / download date of every source.

## Labels

### Silver labels (automatic, for training)

**Extraction spans.** For each advisory with structured `affected` data (GHSA/OSV ranges, CVE5 `affected`, NVD CPE configurations):
1. Take the product/package names and version boundaries from the structured fields.
2. Find them in the description text (exact match → normalized match → fuzzy match with threshold).
3. Keep the advisory only if every structured product is found; record the alignment method per span.
4. Report alignment coverage and a manual precision check on 100 random alignments.

*Day-1 check (critical):* run this on 1,000 advisories and measure how many align cleanly. If coverage is poor, adjust the alignment before anyone trains a tagger.

**Linking pairs.** (mention string in text, identifier) from the aligned extraction labels; aliases mined from records that carry both a purl and a CPE.

**CWE / CVSS.** From NVD, CNA (CVE5) and Vulnrichment records. Drop placeholder CWEs (`NVD-CWE-noinfo`, `NVD-CWE-Other`) from training targets; keep a note of how many were dropped. When NVD and CNA disagree, use NVD as the primary label and keep the CNA label for the agreement study.

**Exploitation signal.** Positive if the CVE is in KEV *and* the text/reference titles mention exploitation; negatives sampled from non-KEV CVEs. Treat as a weak label and say so in the report.

### Gold sets (hand-verified, test-only, in `data/gold/`)

| Gold set | Size | What is annotated | Who |
|---|---|---|---|
| Extraction gold | ~500 test-window advisories | Spans + normalized ranges | P1 + P2, double-annotate 100 for agreement |
| Linking gold | ~300 mentions | Correct identifier or NIL | P3 |
| Bulletin set | ~150 vendor bulletins | Same as extraction gold + linking | P1 |

Annotation guidelines live in `docs/annotation_guidelines.md` (written by P1 in week 3; see `docs/tasks/P1_data_benchmark.md`). Report Cohen's κ / span-level agreement on the double-annotated subset.

## Size expectations (rough)

- NVD: well over 250k CVEs in total; tens of thousands per year recently.
- GitHub reviewed advisories: on the order of 20k+ across ecosystems.
- Restrict package-level work to PyPI, npm and Maven.

## Privacy / ethics

Public data only. No exploit code is downloaded or generated. References that point to exploit repos are kept as URLs only (feature: "PoC exists"), never fetched.
