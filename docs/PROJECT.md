# Project overview

## One-liner

Turn free-text security advisories into a ranked, evidence-grounded "fix this first" list for a specific project's dependencies.

## Problem

New vulnerabilities are published as plain-English advisories, for example:

> "A heap overflow in libfoo before 2.4.3, and 3.x before 3.1.1, allows remote attackers to execute arbitrary code."

Before anyone can act, that text must become structured data: vendor, product, affected version ranges, weakness type (CWE), severity (CVSS vector), exploitation status, and fixed version. NIST's NVD has done much of this enrichment manually and fell far behind in 2024, leaving many CVEs without product or severity data for months. Security teams then face a second problem: of hundreds of advisories a week, which ones affect *their* software, and what should be patched first?

Users: DevSecOps / security engineers, open-source maintainers, CERT teams.

## What the system does

1. Ingests advisories as they are published, using only their text (no waiting for NVD enrichment).
2. Extracts affected products, version expressions and fixed versions.
3. Normalizes version expressions into machine-checkable ranges.
4. Links product mentions to standard identifiers (CPE names / package URLs), or marks them NIL.
5. Predicts CWE, CVSS v3.1 base vector and exploitation signals, with calibrated confidence.
6. Matches normalized ranges against the components in a project's SBOM.
7. Ranks affected items by severity × exploitation × asset criticality × confidence.
8. Shows a patch queue: each item has highlighted evidence spans, confidences, a recommended fix version and a ticket draft. Low-confidence items are routed to human review.

Example output entry:

```
payments-api uses libfoo 2.4.1
  → affected (range < 2.4.3)                       [evidence: "before 2.4.3"]
  → CWE-787 out-of-bounds write (p=0.82)
  → AV:N / AC:L / PR:N / UI:N ...  (calibrated)
  → listed in CISA KEV; EPSS 0.94
  → action: upgrade libfoo to >= 2.4.3
```

## Research questions

- **RQ1.** How accurately can affected products and version ranges be extracted and normalized from advisory text, using distant supervision from structured records?
- **RQ2.** How well can product mentions be linked to a very large identifier space (CPE / package registries), including NIL detection?
- **RQ3.** Can CWE and CVSS be predicted from text with useful accuracy *and* calibration, especially on rare CWE classes?
- **RQ4.** Does a modular pipeline of specialized NLP components beat a single LLM doing the whole job end-to-end, on accuracy, calibration, latency and cost?
- **RQ5.** End-to-end: for real SBOMs, how precise and complete are the system's alerts, and how often is its day-0 output consistent with NVD's later enrichment?

## Scope

In scope:
- Package ecosystems: **PyPI, npm, Maven** (+ CPE for system libraries where needed).
- CVSS **v3.1** base metrics (v4.0 optional stretch).
- English advisories.
- Sources: NVD, CVE JSON 5 records, GitHub Advisory Database, OSV, CISA KEV, FIRST EPSS; vendor bulletins / mailing-list posts for the domain-shift test.

Out of scope:
- Exploit generation or any offensive tooling.
- Code reachability analysis.
- Building our own SBOM generator (use Syft).
- Non-English advisories.

## Definition of done

- Each of the 5 components has: a baseline, a main model, at least one ablation, metrics in `results/`, and an error-analysis note.
- The modular-vs-single-LLM comparison (RQ4) is complete.
- The end-to-end replay over the test window runs with one command and produces the metrics in `docs/EVALUATION.md`.
- The dashboard demo works on advisories published after the test-window start, plus live paste-in of any advisory.
- Final report + slides.

## Novelty (for the report)

Turns raw advisory text into a concrete action (which component to upgrade, to which version) by combining structured extraction, large-scale entity linking and calibrated classification in one end-to-end system, and directly compares this modular pipeline against a single-LLM approach.
