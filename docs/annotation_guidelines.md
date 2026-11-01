# Annotation Guidelines

**Owner:** Ayush Khelwal (P1)  
**Applies to:** P1 (Benchmark), P2 (Extraction), P3 (Entity Linking), P4 (Classification)  
**Dataset target:** `data/gold/`

---

## 1. Overview and Objectives

This document establishes the official annotation guidelines and decision protocols for creating human-verified **gold standard evaluation sets** in VulnTriage. The gold benchmark serves as the definitive test ground for:
- **Information Extraction (RQ1):** Identifying `VENDOR`, `PRODUCT`, `VERSION_EXPR`, and `FIXED_VERSION` spans with exact character offsets, and normalizing them into machine-checkable `vers:` ranges via `univers`.
- **Entity Linking (RQ2):** Resolving unstructured product mentions to canonical package identifiers (PURL for PyPI/npm/Maven, or CPE), or assigning `NIL` when an entity cannot be linked.
- **Weakness & Severity Classification (RQ3):** Providing human consensus baselines for CWE categories and CVSS v3.1 vector assignments.
- **Domain Shift:** Validating model generalization on unstructured vendor bulletins and mailing list advisories.

All gold annotations are produced by the 5 team members with a 100-item double-annotation subset to measure inter-annotator agreement (Cohen's $\kappa$ and token/span $F_1$).

---

## 2. Entity Span Labels (P2)

Annotators tag contiguous character sequences in `Advisory.text`. Spans must never include leading/trailing whitespace or extraneous surrounding punctuation (parentheses, commas, trailing periods).

| Label | Description | What to include | What to exclude |
|---|---|---|---|
| `VENDOR` | The organization, author, or publisher providing the software. | "Apache", "Django Software Foundation", "Microsoft", "Red Hat" | Generic terms like "project", "community", or author emails. |
| `PRODUCT` | The specific software package, library, framework, or application. | "Struts 2", "log4j-core", "requests", "express", "kernel" | Vendor prefixes unless inseparable; file extensions (".py", ".jar"). |
| `VERSION_EXPR` | Text specifying affected version ranges, operators, or condition phrases. | "before 3.1.2", "versions 2.0 through 2.8", ">= 1.0, < 1.4.2", "4.x prior to 4.2" | Remediation recommendations, fixed version notices. |
| `FIXED_VERSION` | Explicit mention of the patch release or upgrade target. | "2.5.33" in "Fixed in 2.5.33", "1.14.1" in "Upgrade to 1.14.1" | The word "fixed in", operators ("<="), or future roadmap versions. |

---

## 3. Boundary & Disambiguation Rules

1. **Punctuation Stripping:**  
   - Do NOT include trailing punctuation: `[requests]` before `[2.31.0]`, NOT `[requests,]` or `[2.31.0.]`.
   - Do NOT include enclosing brackets or parentheses unless part of the official name: tag `foo-bar`, not `(foo-bar)`.
2. **Vendor vs. Product Splitting:**  
   - If a vendor and product appear together (e.g. "Apache Tomcat"), split into `[Apache]` (VENDOR) and `[Tomcat]` (PRODUCT) whenever feasible.  
   - If the product name cannot be separated cleanly (e.g., "OpenSSL"), tag the entire token as `PRODUCT`.
3. **Compound & Branching Version Expressions:**  
   - When multiple branches are specified (e.g., "2.4.x before 2.4.58 and 2.2.x before 2.2.34"), tag each contiguous version clause as a separate `VERSION_EXPR` span.
   - Do not merge the word "and" or commas across independent branch expressions into a single span.
4. **Inclusive vs. Exclusive Range Phrases:**  
   - "through X", "up to and including X", "X and earlier" represent *inclusive* upper bounds ($\le X$).
   - "before X", "prior to X", "earlier than X" represent *exclusive* upper bounds ($< X$).
   - "from A to B" represents inclusive range ($[A, B]$).
5. **No Hallucinated Spans:**  
   - If an advisory does not explicitly name the vendor or fixed version in the text, leave the field null. Never infer or inject unmentioned tokens.

---

## 4. 12 Worked Real-World Examples

### Example 1: Standard Upper Bound
- **Text:** `"In requests before 2.32.0, verifying HTTPS certificates could be bypassed."`
- **Annotations:**
  - `PRODUCT`: `"requests"` [3:11]
  - `VERSION_EXPR`: `"before 2.32.0"` [12:25]
- **Normalized Range:** `vers:pypi/<2.32.0`
- **Fixed Version:** `2.32.0`

### Example 2: Vendor, Product, and Inclusive Range
- **Text:** `"Apache Struts versions 2.0.0 through 2.5.32 are vulnerable to RCE. Fixed in version 2.5.33."`
- **Annotations:**
  - `VENDOR`: `"Apache"` [0:6]
  - `PRODUCT`: `"Struts"` [7:13]
  - `VERSION_EXPR`: `"2.0.0 through 2.5.32"` [23:47]
  - `FIXED_VERSION`: `"2.5.33"` [85:91]
- **Normalized Range:** `vers:maven/>=2.0.0|<=2.5.32`
- **Fixed Version:** `2.5.33`

### Example 3: Prior to with Remediation Advice
- **Text:** `"Express.js prior to 4.19.2 contains an open redirect vulnerability. Please upgrade to 4.19.2."`
- **Annotations:**
  - `PRODUCT`: `"Express.js"` [0:10]
  - `VERSION_EXPR`: `"prior to 4.19.2"` [11:26]
  - `FIXED_VERSION`: `"4.19.2"` [83:89]
- **Normalized Range:** `vers:npm/<4.19.2`

### Example 4: Multiple Branch Series ("X.x before Y")
- **Text:** `"Django 4.2 before 4.2.11 and 5.0 before 5.0.3 allow denial of service."`
- **Annotations:**
  - `PRODUCT`: `"Django"` [0:6]
  - `VERSION_EXPR`: `"4.2 before 4.2.11"` [7:24]
  - `VERSION_EXPR`: `"5.0 before 5.0.3"` [29:45]
- **Normalized Range:** `vers:pypi/>=4.2.0|<4.2.11|>=5.0.0|<5.0.3`

### Example 5: "And earlier" / Up to
- **Text:** `"In lodash 4.17.20 and earlier, prototype pollution is possible via zipObjectDeep."`
- **Annotations:**
  - `PRODUCT`: `"lodash"` [3:9]
  - `VERSION_EXPR`: `"4.17.20 and earlier"` [10:29]
- **Normalized Range:** `vers:npm/<=4.17.20`

### Example 6: "All versions"
- **Text:** `"All versions of package evil-test are malicious and execute arbitrary code on install."`
- **Annotations:**
  - `VERSION_EXPR`: `"All versions"` [0:12]
  - `PRODUCT`: `"evil-test"` [24:33]
- **Normalized Range:** `vers:npm/*`

### Example 7: Explicit List of Versions
- **Text:** `"Spring Framework versions 5.3.18, 5.2.20 and 5.3.17 are vulnerable to Spring4Shell."`
- **Annotations:**
  - `PRODUCT`: `"Spring Framework"` [0:16]
  - `VERSION_EXPR`: `"5.3.18, 5.2.20 and 5.3.17"` [26:51]
- **Normalized Range:** `vers:maven/5.3.18|5.2.20|5.3.17`

### Example 8: Multi-Product in One Advisory
- **Text:** `"Vulnerabilities in werkzeug before 3.0.1 and flask before 3.0.0 permit cookie tampering."`
- **Annotations:**
  - `PRODUCT`: `"werkzeug"` [19:27]
  - `VERSION_EXPR`: `"before 3.0.1"` [28:40]
  - `PRODUCT`: `"flask"` [45:50]
  - `VERSION_EXPR`: `"before 3.0.0"` [51:63]
- **Affected Items:** Grouped by proximity: `(werkzeug, <3.0.1)` and `(flask, <3.0.0)`.

### Example 9: Range with "From A to B"
- **Text:** `"In urllib3 from 1.26.0 to 1.26.17, authorization headers are stripped on cross-origin redirects."`
- **Annotations:**
  - `PRODUCT`: `"urllib3"` [3:10]
  - `VERSION_EXPR`: `"from 1.26.0 to 1.26.17"` [11:32]
- **Normalized Range:** `vers:pypi/>=1.26.0|<=1.26.17`

### Example 10: Fixed Version in Note
- **Text:** `"A heap overflow exists in OpenSSL. The issue is addressed in openssl-3.0.8."`
- **Annotations:**
  - `PRODUCT`: `"OpenSSL"` [26:33]
  - `FIXED_VERSION`: `"3.0.8"` [69:74]
- **Normalized Range:** `vers:generic/<3.0.8`

### Example 11: Vendor Advisory Package Name (Debian / RPM Phrasing)
- **Text:** `"Debian Security Advisory: apache2 security update to 2.4.58-1~deb12u1."`
- **Annotations:**
  - `VENDOR`: `"Debian"` [0:6]
  - `PRODUCT`: `"apache2"` [26:33]
  - `FIXED_VERSION`: `"2.4.58-1~deb12u1"` [53:70]
- **Normalized Range:** `vers:deb/apache2/<2.4.58-1~deb12u1`

### Example 12: Nil Link Case (Proprietary / In-house Mention)
- **Text:** `"In ACME Corporate InternalGateway 2.1, cleartext transmission of credentials occurs."`
- **Annotations:**
  - `VENDOR`: `"ACME Corporate"` [3:17]
  - `PRODUCT`: `"InternalGateway"` [18:33]
  - `VERSION_EXPR`: `"2.1"` [34:37]
- **Entity Linking Target:** `NIL` (`is_nil: true`, `gold_identifier: null`).

---

## 5. Entity Linking Annotation (P3)

Annotators evaluate each extracted `PRODUCT` mention in its sentential context:
1. **Target Namespace Hierarchy:**
   - Prefer ecosystem Package URL (**PURL**) for PyPI, npm, and Maven:
     - `pkg:pypi/package-name`
     - `pkg:npm/package-name`
     - `pkg:maven/group-id/artifact-id`
   - Use Common Platform Enumeration (**CPE v2.3**) for operating system components or standalone products:
     - `cpe:2.3:a:vendor:product:version:...`
2. **NIL Decision Criteria:**
   - Mark `is_nil: true` and `gold_identifier: null` if:
     - The product is not present in PyPI, npm, Maven, or official NVD CPE dictionary.
     - The mention is ambiguous and refers to a broad family without a concrete package.
     - The mention refers to an unreleased internal prototype or non-public software.

---

## 6. Annotation Workflow & Tooling

- **Tooling Choice:** Lightweight JSONL spreadsheet review with **doccano / Label Studio export schema**. Selected for zero-setup local reproducibility, deterministic version control via Git, and seamless integration with Pydantic validators.
- **Partitioning across 5 team members:**
  - Total extraction test sample: **500 items** (~100 items per member).
  - Total linking test sample: **300 mentions** (~60 items per member).
  - Domain-shift vendor bulletin set: **150 items**.
- **Double-Annotation Subset:**
  - Exactly **100 items** are assigned to two independent annotators.
  - Inter-annotator agreement is evaluated automatically:
    - **Span $F_1$:** Harmonic mean of precision and recall over exact `(start, end, label)` tuples.
    - **Cohen's $\kappa$:** Categorical agreement on binary `is_nil` and discrete field tags.
- **Adjudication Procedure:**
  - Disagreements ($F_1 < 1.0$ or differing span boundaries) are reviewed by the P1 owner (Ayush Khelwal).
  - Adjudicated records are marked `adjudicated: true` in `data/gold/`.
