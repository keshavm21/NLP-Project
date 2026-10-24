"""Regex extraction baseline (the floor). Simple by design.

- FIXED_VERSION: version numbers after "fixed/patched/resolved/addressed in" or "upgrade to".
- VERSION_EXPR: version-number patterns plus the range keywords around them
  ("before 2.4.3", "3.x before 3.1.1", "1.0 through 1.5", "2.4.3 and earlier", lists).
- PRODUCT: a known product name, else the tokens right before the version expression
  (the closest non-stopword token, extended left over capitalized tokens), else the name after
  "of/in" when the expression comes first ("versions before 2.4.3 of libfoo").
- No VENDOR detection. vers_range comes from the version grammar; grouping from grouping.py.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from vulntriage.extract.base import Extractor
from vulntriage.extract.grouping import group_affected, sentence_ids
from vulntriage.schemas import Advisory, ExtractionResult, Span

# Version token: needs a dot unless a range keyword introduces it ("before 5" is fine, a bare
# "2021" in "CVE-2021-44228" is not). Boundaries keep it from matching inside words or IDs.
_B = r"(?<![\w.\-/])"
_E = r"(?![\w\-]|\.\d)"
_SUFFIX = r"(?:(?:[-_.+~]|(?=[A-Za-z]))(?![xX]\b)[A-Za-z0-9]+)*"
_VER_DOT = rf"{_B}v?\d+(?:\.\d+)+{_SUFFIX}{_E}"
_VER_ANY = rf"{_B}v?\d+(?:\.\d+)*{_SUFFIX}{_E}"
_SERIES = rf"{_B}\d+(?:\.\d+)*\.(?:x|\*){_E}"

_KW = (
    r"(?:up to and including|up to \((?:in|ex)cluding\)|to and including|through|thru|before"
    r"|prior to|earlier than|lower than|less than|older than|below|up to|until|to)"
)
_OPV = r"(?:version\s+)?"
_ATOM = (
    rf"(?:(?:from(?: \((?:in|ex)cluding\))?\s+)?(?:{_SERIES}|{_VER_ANY})\s+{_KW}\s+{_OPV}{_VER_ANY}"
    rf"|{_KW}\s+{_OPV}{_VER_ANY}"
    rf"|{_VER_DOT},?\s+(?:and|or)\s+(?:all\s+)?(?:earlier|prior|below|older|lower|previous|later"
    rf"|above|newer|higher)\b"
    rf"|(?:>=|<=|<|>|=)\s*{_VER_ANY}(?:\s*,\s*(?:<=|<)\s*{_VER_ANY})?"
    rf"|{_SERIES}|{_VER_DOT})"
)
_SEP = r"(?:\s*;\s*|,\s*(?:and|or)\s+|,\s*|\s+(?:and|or)\s+)"
_EXPR_RE = re.compile(rf"{_ATOM}(?:{_SEP}{_ATOM})*", re.I)

_FIXED_HEAD_RE = re.compile(
    r"\b(?:(?:fixed|patched|resolved|addressed|remediated)\s+in|upgrad(?:e|ing)\s+to"
    r"|updat(?:e|ing)\s+to)\s+(?:(?:versions?|releases?)\s+)?",
    re.I,
)
_FIXED_LIST_RE = re.compile(rf"(?:{_SEP})?(?P<v>{_VER_ANY})", re.I)

_TOKEN_RE = re.compile(r"@?[A-Za-z][\w.+/:@-]*[\w+]|[A-Za-z]")
_SKIP_BEFORE = {"version", "versions", "release", "releases", "v", "from", "the"}
_STOPWORDS = {
    "a", "an", "the", "in", "of", "for", "on", "to", "and", "or", "with", "by", "from", "via",
    "at", "as", "is", "are", "was", "were", "be", "been", "this", "that", "these", "those", "it",
    "its", "affects", "affected", "affecting", "allows", "allow", "vulnerability",
    "vulnerabilities", "issue", "issues", "flaw", "bug", "versions", "version", "release",
    "releases", "all", "prior", "before", "through", "earlier", "later", "fixed", "users",
    "when", "if", "which", "where", "could", "can", "may", "might", "attackers", "attacker",
    "remote", "found", "discovered", "exists", "contains", "has", "have", "had", "up",
    "including", "excluding", "including)", "excluding)", "starting", "since", "multiple",
    "upgrade", "update", "patched", "should", "please", "recommended", "using", "use", "cvss",
    "score", "cwe",
}  # fmt: skip
_MAX_PRODUCT_TOKENS = 4
_COORD_LEFT_RE = re.compile(
    r"(?P<tok>@?[A-Za-z][\w.+/:@-]*[\w+])\s*(?:,\s*(?:and|or)?|and|or)\s*$", re.I
)
_MAX_COORDINATED = 4


class RegexExtractor(Extractor):
    """Regex/heuristic extractor. `known_products` (optional) are matched first."""

    name = "regex"

    def __init__(self, scheme: str = "generic", known_products: Iterable[str] = ()) -> None:
        self.scheme = scheme
        known = sorted({k.strip() for k in known_products if k.strip()}, key=len, reverse=True)
        self._known_re = (
            re.compile(r"(?<!\w)(?:" + "|".join(map(re.escape, known)) + r")(?!\w)", re.I)
            if known
            else None
        )

    def extract(self, advisory: Advisory) -> ExtractionResult:
        text = advisory.text
        fixed = self._fixed_spans(text)
        masked = [(s.start, s.end) for s in fixed] + [
            (m.start(), m.end()) for m in _FIXED_HEAD_RE.finditer(text)
        ]
        versions = [
            Span.from_text(text, m.start(), m.end(), "VERSION_EXPR")
            for m in _EXPR_RE.finditer(text)
            if not any(m.start() < e and s < m.end() for s, e in masked)
        ]
        sent = sentence_ids(text)
        products: dict[tuple[int, int], Span] = {}
        for v in versions:
            p = self._product_left(text, v.start, sent) or self._product_right(text, v.end)
            if p is None:
                continue
            for q in [p, *self._coordinated(text, p)]:
                products.setdefault((q.start, q.end), q)
        spans = sorted([*products.values(), *versions, *fixed], key=lambda s: (s.start, s.end))
        return ExtractionResult(
            advisory_id=advisory.id,
            spans=spans,
            affected=group_affected(text, spans, self.scheme),
            model=self.name,
        )

    def _fixed_spans(self, text: str) -> list[Span]:
        spans = []
        for head in _FIXED_HEAD_RE.finditer(text):
            pos = head.end()
            while m := _FIXED_LIST_RE.match(text, pos):
                spans.append(Span.from_text(text, m.start("v"), m.end("v"), "FIXED_VERSION"))
                pos = m.end()
        return spans

    def _product_left(self, text: str, start: int, sent: list[int]) -> Span | None:
        sid = sent[start]
        tokens = [
            m
            for m in _TOKEN_RE.finditer(text, 0, start)
            if sent[m.start()] == sid and m.end() <= start
        ]
        if self._known_re is not None and tokens:  # nearest known name earlier in the sentence
            known = list(self._known_re.finditer(text, tokens[0].start(), start))
            if known:
                return Span.from_text(text, known[-1].start(), known[-1].end(), "PRODUCT")
        while tokens and tokens[-1].group().lower() in _SKIP_BEFORE:
            tokens.pop()
        if not tokens:
            return None
        head = tokens[-1]
        if head.group().lower() in _STOPWORDS:
            return None
        first = head
        for tok in reversed(tokens[:-1][-(_MAX_PRODUCT_TOKENS - 1) :]):
            gap = text[tok.end() : first.start()]
            if gap != " " or not tok.group()[0].isupper() or tok.group().lower() in _STOPWORDS:
                break
            first = tok
        return Span.from_text(text, first.start(), head.end(), "PRODUCT")

    def _coordinated(self, text: str, product: Span) -> list[Span]:
        """Single-token names coordinated before `product`: "libfoo, libbaz and <product>"."""
        out: list[Span] = []
        start = product.start
        while len(out) < _MAX_COORDINATED:
            m = _COORD_LEFT_RE.search(text, 0, start)
            if m is None or m["tok"].lower() in _STOPWORDS:
                break
            out.append(Span.from_text(text, m.start("tok"), m.end("tok"), "PRODUCT"))
            start = m.start("tok")
        return out

    def _product_right(self, text: str, end: int) -> Span | None:
        m = re.compile(r"\s+(?:of|in|for)\s+(?:the\s+)?", re.I).match(text, end)
        if m is None:
            return None
        known = self._known_re.match(text, m.end()) if self._known_re is not None else None
        if known is not None:
            return Span.from_text(text, known.start(), known.end(), "PRODUCT")
        tok = _TOKEN_RE.match(text, m.end())
        if tok is None or tok.group().lower() in _STOPWORDS:
            return None
        return Span.from_text(text, tok.start(), tok.end(), "PRODUCT")
