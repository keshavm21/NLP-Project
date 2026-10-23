# Glossary

Read this first if you're new to security. Everything in the project uses these words.

## Security terms

**Vulnerability** — a bug that lets someone do something they shouldn't (read data, run code, crash a service).

**Advisory** — a written notice that a vulnerability exists. Usually a short paragraph saying what's affected, which versions, what an attacker can do, and how to fix it. **This is our model input.**

**CVE** (Common Vulnerabilities and Exposures) — the global ID system for vulnerabilities, e.g. `CVE-2021-44228` (Log4Shell). Each CVE has a short English description.

**CNA** (CVE Numbering Authority) — an organization allowed to assign CVE IDs (GitHub, Microsoft, Red Hat, …). CNAs often add their own product, version and severity data to the record.

**NVD** (National Vulnerability Database) — run by NIST (US). Analysts read each CVE and add structured data: affected products (CPE), weakness (CWE) and severity (CVSS). In 2024 they fell far behind, so many CVEs sat without this data for months. **That gap is our motivation.**

**GHSA** — GitHub Security Advisory ID, e.g. `GHSA-jfh8-c2jp-5v3q`. GitHub's database has reviewed advisories for open-source packages with exact package names and version ranges.

**OSV** (Open Source Vulnerabilities) — a common format and database for package vulnerabilities across ecosystems (PyPI, npm, Maven, …). Very clean, machine-readable affected ranges. **Our best source of automatic labels.**

**CWE** (Common Weakness Enumeration) — a catalog of *types* of weakness, arranged in a tree. Examples:
- CWE-79: Cross-site scripting
- CWE-89: SQL injection
- CWE-787: Out-of-bounds write
- CWE-22: Path traversal

There are hundreds; a few are very common, most are rare (long tail). `NVD-CWE-noinfo` / `NVD-CWE-Other` are placeholders, not real types.

**CVSS** (Common Vulnerability Scoring System) — a severity score from 0 to 10, computed from a *vector* of 8 base metrics. We use version 3.1:

| Metric | Question | Values |
|---|---|---|
| AV — Attack Vector | From where can it be attacked? | Network, Adjacent, Local, Physical |
| AC — Attack Complexity | Are special conditions needed? | Low, High |
| PR — Privileges Required | Does the attacker need an account? | None, Low, High |
| UI — User Interaction | Does a victim need to click something? | None, Required |
| S — Scope | Can it affect other components? | Unchanged, Changed |
| C / I / A | Impact on Confidentiality / Integrity / Availability | None, Low, High |

Example vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → score 9.8 (Critical). The score is computed from the vector by a fixed formula, so **we predict the 8 metrics, not the number**.

Severity bands: None 0.0 · Low 0.1–3.9 · Medium 4.0–6.9 · High 7.0–8.9 · Critical 9.0–10.0.

**CPE** (Common Platform Enumeration) — a naming scheme for software/hardware products, e.g. `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*` (`a` = application, then vendor, product, version). NVD uses CPEs to say what a CVE affects. The dictionary has over a million entries.

**purl** (Package URL) — a simpler identifier for packages: `pkg:pypi/django@4.2.1`, `pkg:npm/lodash@4.17.20`, `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`. **Our preferred identifier for packages.**

**Ecosystem** — a package world with its own registry and version rules: PyPI (Python), npm (JavaScript), Maven (Java). We use these three.

**Dependency** — a library your software uses. Most apps have hundreds, including dependencies of dependencies ("transitive").

**SBOM** (Software Bill of Materials) — a machine-readable list of every component and version inside a piece of software. Formats: CycloneDX, SPDX. We generate them with the tool **Syft**.

**KEV** (Known Exploited Vulnerabilities) — CISA's list of CVEs that attackers are *actually* using. Strong signal for "fix this first".

**EPSS** (Exploit Prediction Scoring System) — FIRST's daily probability (0–1) that a CVE will be exploited in the next 30 days.

**PoC** (Proof of Concept) — public demo code showing the bug can be exploited. We may note *that* one exists; we never download or write one.

**Patch / fixed version** — the release where the bug is fixed. "Upgrade to ≥ 2.4.3".

**Triage** — deciding what to deal with first. That's what our output is.

## Version-range language

Advisories describe versions in many ways. All of these must become exact ranges:

| Text | Range |
|---|---|
| "before 2.4.3", "prior to 2.4.3" | `< 2.4.3` |
| "through 2.4.3", "up to and including 2.4.3", "2.4.3 and earlier" | `<= 2.4.3` |
| "3.x before 3.1.1" | `>= 3.0.0, < 3.1.1` |
| "from 1.2 to 1.5" | `>= 1.2, <= 1.5` (check wording: "to" is ambiguous) |
| "fixed in 2.4.3" | affected `< 2.4.3` (usually) |
| "versions 1.0, 1.1 and 1.3" | exactly those versions |

We store ranges in the **`vers:`** format used by the `univers` library, e.g. `vers:pypi/>=3.0.0|<3.1.1`.

## NLP / ML terms used in this project

**Silver labels** — labels created automatically (e.g., by finding the package name from a GHSA record inside its description text). Lots of them, somewhat noisy. Used for training.

**Gold labels** — labels checked by hand by us. Few, accurate. Used only for testing.

**Distant supervision** — training from silver labels produced by aligning an existing database with text.

**BIO tagging** — sequence-labeling scheme: each token is **B**egin, **I**nside or **O**utside of an entity span.

**Entity linking** — mapping a text mention ("Struts 2") to an entry in a knowledge base (a purl or CPE).

**NIL** — the linker's answer when the right entry isn't in our index at all.

**Bi-encoder / cross-encoder** — bi-encoder: embeds mention and candidate separately (fast, used to retrieve top-k). Cross-encoder: reads both together (slow, accurate, used to rerank the top-k).

**BM25** — classic keyword-based retrieval scoring. Our standard non-neural retrieval baseline.

**Calibration** — when a model says "80% sure", it should be right about 80% of the time. Measured with **ECE** (expected calibration error). Fixed with **temperature scaling**.

**Conformal prediction** — returns a *set* of labels guaranteed to contain the true one with a chosen probability (e.g., 90%).

**Temporal split** — train on older data, test on newer data. Simulates real use and stops LLMs from having "seen" the test answers during their own training (**contamination**).

**Ablation** — remove one part of the system and measure how much worse it gets.

**NDCG@k** — ranking metric: rewards putting the most important items near the top of a list.

**LoRA** — cheap fine-tuning of a large model by training small added matrices.

**Grounded generation** — generated text that only states facts traceable to evidence; checked by a **verifier**.
