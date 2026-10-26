"""Deterministic parser from VERSION_EXPR text to version ranges, rendered as univers vers: strings.

The ecosystem is not in the text, so the version scheme is a parameter ("generic" by default;
"pypi", "npm", "maven" are the project ecosystems). Each successful parse carries a `family`
label naming the phrasing pattern, because extraction results are broken down by family.

Never guess: anything ambiguous ("up to 2.0", "until 2.0", "fixed in 1.2 and 2.0") or any
version the scheme cannot represent faithfully returns None.

    >>> parse_version_expr("3.x before 3.1.1").vers
    'vers:generic/>=3.0.0|<3.1.1'
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from univers.version_constraint import VersionConstraint
from univers.version_range import RANGE_CLASS_BY_SCHEMES

FAMILIES: tuple[str, ...] = (
    "before",  # before 2.4.3, less than 2.4.3, below 2.4.3
    "prior_to",  # prior to 2.4.3
    "through",  # through 2.4.3
    "up_to_including",  # up to and including 2.4.3, up to (including) 2.4.3
    "up_to_excluding",  # up to (excluding) 2.4.3
    "and_earlier",  # 2.4.3 and earlier / and prior / and below
    "and_later",  # 2.0 and later
    "branch_before",  # 3.x before 3.1.1, 3.2 before 3.2.19
    "from_to",  # from 1.0 to 1.5, 1.0 to 1.5, from 1.0 before 2.0
    "a_through_b",  # 1.0 through 1.5
    "operator",  # >= 1.0, < 2.0 (GHSA style)
    "series",  # 2.x
    "single",  # 2.4.3
    "list",  # 2.4.3 and 3.1.1; a, b and c
    "multi_range",  # before 1.2.3, 2.x before 2.4.5, and 3.x before 3.1.1
    "fixed_in",  # fixed in 2.4.3
    "all_versions",  # all versions
    "hyphen_range",  # 1.0-1.5, 1.0 - 1.5 (inclusive)
    "maven_interval",  # [1.0,2.0), (,1.0], [1.2], (,1.0],[1.2,)
)

# Schemes whose univers version class is semver: they coerce non-semver strings lossily
# ("1.2.3.4" -> "1.2.3+4", "1.1.1t" -> "1.1.1-t"), so only strict semver-shaped input is accepted.
_SEMVER_SCHEMES = {"generic", "npm"}
_STRICT_SEMVER = re.compile(r"\d+(?:\.\d+){0,2}(?:-[0-9a-z]+(?:[.-][0-9a-z]+)*)?", re.I)

# --- lexical pieces -------------------------------------------------------------------------

_SERIES = r"\d+(?:\.\d+)*\.(?:x|\*)"
# A version token: numeric core plus optional suffixes ("-rc.1", "b1", ".RELEASE", "u202").
# A bare ".x" / ".*" component is a series, not a suffix.
_VER = r"v?\d+(?:\.\d+)*(?:(?:[-_.+~]|(?=[a-z]))(?!x\b)[a-z0-9]+)*"
_TOK = rf"(?:{_SERIES}|{_VER})"

_UPPER_KW = {
    # keyword -> (comparator, family when there is no lower bound)
    "up to and including": ("<=", "up_to_including"),
    "up to (including)": ("<=", "up_to_including"),
    "to and including": ("<=", "up_to_including"),
    "up to (excluding)": ("<", "up_to_excluding"),
    "through": ("<=", "through"),
    "thru": ("<=", "through"),
    "before": ("<", "before"),
    "earlier than": ("<", "before"),
    "lower than": ("<", "before"),
    "less than": ("<", "before"),
    "older than": ("<", "before"),
    "below": ("<", "before"),
    "prior to": ("<", "prior_to"),
    "to": ("<=", "from_to"),  # needs a lower bound
    # Ambiguous between inclusive and exclusive: recognised only so they can be refused.
    "up to": (None, None),
    "until": (None, None),
}
_UPPER_ALT = "|".join(re.escape(k) for k in sorted(_UPPER_KW, key=len, reverse=True))

_BOUNDS_RE = re.compile(
    rf"^(?:(?P<from>from(?: \((?P<lo_kind>including|excluding)\))?|starting (?:with|from|at|in)"
    rf"|since)\s+)?(?:(?:versions?\s+)?(?P<lo>{_TOK}),?\s+(?:(?:and|but)\s+)?)?"
    rf"(?P<kw>{_UPPER_ALT})\s+"
    rf"(?:versions?\s+)?(?P<hi>{_VER})$",
    re.I,
)
_ALL_RE = re.compile(
    r"^(?:(?:all|any|every)(?: (?:affected|known))?(?: versions?| releases?)?|\*)$", re.I
)
_FIXED_RE = re.compile(
    rf"^(?:[^\d]*\b)?(?:fixed|patched|resolved|addressed|remediated)\s+in\s+"
    rf"(?:versions?\s+|releases?\s+)?(?P<v>{_VER})$",
    re.I,
)
_OP = r"(?:>=|<=|==|=|<|>)"
_OPERATOR_RE = re.compile(
    rf"^(?P<op1>{_OP})\s*(?P<v1>{_VER})(?:\s*,?\s*(?P<op2>{_OP})\s*(?P<v2>{_VER}))?$", re.I
)
_EARLIER_RE = re.compile(
    rf"^(?P<v>{_VER}),? (?:and|or) (?:all )?(?:earlier|prior|below|older|lower|previous)"
    r"(?: versions?| releases?)?$",
    re.I,
)
_LATER_RE = re.compile(
    rf"^(?P<v>{_VER})(?:,? (?:and|or) (?:all )?(?:later|above|newer|higher|greater|subsequent)"
    r"(?: versions?| releases?)?|\+)$",
    re.I,
)
_SERIES_RE = re.compile(rf"^(?P<s>{_SERIES})$", re.I)
_SINGLE_RE = re.compile(rf"^(?P<v>{_VER})$", re.I)
# A dash between two versions is a range only when it can't be a prerelease/revision suffix:
# spaced or en dash, or both sides dotted ("1.0-1.5", but not "1.0.0-1").
_HYPHEN_RE = re.compile(
    rf"^(?P<lo>{_VER})\s+[-–]\s+(?P<hi>{_VER})$|^(?P<lo2>{_VER})\s*–\s*(?P<hi2>{_VER})$"
    rf"|^(?P<lo3>v?\d+(?:\.\d+)+)-(?P<hi3>\d+(?:\.\d+)+)$",
    re.I,
)
_INTERVAL = rf"[\[(]\s*(?:{_VER})?\s*(?:,\s*(?:{_VER})?\s*)?[\])]"
_MAVEN_RE = re.compile(rf"^{_INTERVAL}(?:\s*,\s*{_INTERVAL})*$", re.I)
_MAVEN_PART_RE = re.compile(
    rf"(?P<open>[\[(])\s*(?P<lo>{_VER})?\s*(?P<comma>,)?\s*(?P<hi>{_VER})?\s*(?P<close>[\])])",
    re.I,
)

# Clause separators: ",", ";", " and ", " or ", ", and" -- but only when the next clause starts
# like a clause ("2.4.3 and earlier" must not split; ">= 1.0, < 2.0" stays one clause).
_SPLIT_RE = re.compile(
    r"\s*(?:;|,\s*(?:and|or)\s+|,|\s(?:and|or)\s)\s*(?=v?\d|from\b|versions?\b|>|=)", re.I
)

_LEAD_RE = re.compile(
    r"^(?:(?:affects|affecting|affected|in|on|for|all|the|only)\s+)*"
    r"(?:(?:versions?|releases?|builds?)\s*:?\s+)?",
    re.I,
)
_TRAIL_RE = re.compile(
    r"(?:\s+(?:\(inclusive\)|inclusive|versions?|releases?|series|branch|line"
    r"|(?:are|is) (?:affected|vulnerable)))*\s*[.,;:]*$",
    re.I,
)


# --- result types ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Interval:
    """A contiguous version interval; a bound of None is open. Exact versions have lo == hi."""

    lo: str | None = None
    lo_inclusive: bool = True
    hi: str | None = None
    hi_inclusive: bool = False

    @property
    def is_exact(self) -> bool:
        return self.lo is not None and self.lo == self.hi


@dataclass(frozen=True)
class VersionParse:
    """Result of parsing one VERSION_EXPR. `intervals` are sorted and disjoint (after merging)."""

    family: str
    scheme: str
    intervals: tuple[Interval, ...] = ()  # empty = all versions
    fixed_versions: tuple[str, ...] = field(default=())

    @property
    def vers(self) -> str:
        return render_vers(self)

    def contains(self, version: str) -> bool:
        """True if `version` falls in the parsed range (univers containment)."""
        cls = _range_class(self.scheme)
        return cls.version_class(version) in cls.from_string(self.vers)


# --- public API -----------------------------------------------------------------------------


def parse_version_expr(text: str, scheme: str = "generic") -> VersionParse | None:
    """Parse a VERSION_EXPR phrase into constraints, or None if it can't be parsed safely."""
    _range_class(scheme)  # validate scheme early
    collapsed = re.sub(r"\s+", " ", text.strip()).replace("≤", "<=").replace("≥", ">=")
    if _ALL_RE.match(_TRAIL_RE.sub("", collapsed)):
        return VersionParse("all_versions", scheme)
    expr = _strip(collapsed)
    if not expr:
        return None

    single = _parse_clause(expr, scheme)
    if single is not None:
        family, intervals, fixed = single
        merged = _merge(intervals, scheme)
        return None if merged is None else VersionParse(family, scheme, merged, fixed)

    clauses = [c for c in (_strip(c) for c in _SPLIT_RE.split(expr)) if c]
    if len(clauses) < 2:
        return None
    parsed = [_parse_clause(c, scheme) for c in clauses]
    if any(p is None for p in parsed):
        return None
    # "fixed in 1.2.3 and 2.0.1" names fixes on several branches without saying where each
    # branch starts, so the affected range can't be derived without guessing.
    if any(p[0] in ("fixed_in", "all_versions") for p in parsed):
        return None
    intervals = [iv for p in parsed for iv in p[1]]
    merged = _merge(intervals, scheme)
    if merged is None:
        return None
    family = "list" if all(p[0] == "single" for p in parsed) else "multi_range"
    return VersionParse(family, scheme, merged)


def combine(parses: list[VersionParse | None]) -> VersionParse | None:
    """Union several parses for the same product (e.g. two version spans for one product).

    None if the list is empty, any parse is None, or the schemes differ (never guess).
    """
    if not parses or any(p is None for p in parses):
        return None
    if len(parses) == 1:
        return parses[0]
    scheme = parses[0].scheme
    if any(p.scheme != scheme for p in parses):
        return None
    fixed = tuple(dict.fromkeys(v for p in parses for v in p.fixed_versions))
    if any(p.family == "all_versions" for p in parses):
        return VersionParse("all_versions", scheme, (), fixed)
    merged = _merge([iv for p in parses for iv in p.intervals], scheme)
    return None if merged is None else VersionParse("multi_range", scheme, merged, fixed)


def render_vers(parse: VersionParse) -> str:
    """Render a parse as a univers vers: string (versions normalized by the scheme)."""
    cls = _range_class(parse.scheme)
    if not parse.intervals:
        return f"vers:{parse.scheme}/*"
    vc = cls.version_class
    constraints: list[VersionConstraint] = []
    for iv in parse.intervals:
        if iv.is_exact:
            constraints.append(VersionConstraint(comparator="=", version=vc(iv.lo)))
            continue
        if iv.lo is not None:
            comp = ">=" if iv.lo_inclusive else ">"
            constraints.append(VersionConstraint(comparator=comp, version=vc(iv.lo)))
        if iv.hi is not None:
            comp = "<=" if iv.hi_inclusive else "<"
            constraints.append(VersionConstraint(comparator=comp, version=vc(iv.hi)))
    return str(cls(constraints=constraints))


def to_vers(text: str, scheme: str = "generic") -> str | None:
    """Shortcut: VERSION_EXPR text -> vers: string, or None."""
    parse = parse_version_expr(text, scheme)
    return None if parse is None else parse.vers


def parse_version(token: str, scheme: str = "generic"):
    """Parse one version token with the scheme's univers class; None if not faithful."""
    token = token.strip()
    if token[:1] in ("v", "V") and token[1:2].isdigit():
        token = token[1:]
    if scheme in _SEMVER_SCHEMES and not _STRICT_SEMVER.fullmatch(token):
        return None
    try:
        return _range_class(scheme).version_class(token)
    except Exception:  # univers raises a variety of errors for invalid versions
        return None


# --- internals ------------------------------------------------------------------------------


def _range_class(scheme: str):
    try:
        return RANGE_CLASS_BY_SCHEMES[scheme]
    except KeyError:
        raise ValueError(f"unknown univers scheme: {scheme!r}") from None


def _strip(expr: str) -> str:
    expr = _LEAD_RE.sub("", expr.strip())
    return _TRAIL_RE.sub("", expr).strip()


def _clean(token: str) -> str:
    return token[1:] if token[:1] in ("v", "V") and token[1:2].isdigit() else token


def _series_bounds(token: str) -> tuple[str, str]:
    """'1.2.x' -> ('1.2', '1.3'); '3.x' -> ('3', '4')."""
    parts = token.split(".")[:-1]
    upper = parts[:-1] + [str(int(parts[-1]) + 1)]
    return ".".join(parts), ".".join(upper)


_Clause = tuple[str, list[Interval], tuple[str, ...]]


def _parse_clause(expr: str, scheme: str) -> _Clause | None:
    """Parse one clause into (family, intervals, fixed_versions) or None."""
    if m := _FIXED_RE.match(expr):
        v = _clean(m["v"])
        return ("fixed_in", [Interval(hi=v)], (v,))
    if m := _OPERATOR_RE.match(expr):
        return _operator_clause(m)
    if m := _EARLIER_RE.match(expr):
        return ("and_earlier", [Interval(hi=_clean(m["v"]), hi_inclusive=True)], ())
    if m := _LATER_RE.match(expr):
        return ("and_later", [Interval(lo=_clean(m["v"]))], ())
    if m := _SERIES_RE.match(expr):
        lo, hi = _series_bounds(m["s"])
        return ("series", [Interval(lo=lo, hi=hi)], ())
    if _MAVEN_RE.match(expr):
        return _maven_clause(expr)
    if m := _HYPHEN_RE.match(expr):
        lo = _clean(m["lo"] or m["lo2"] or m["lo3"])
        hi = _clean(m["hi"] or m["hi2"] or m["hi3"])
        return ("hyphen_range", [Interval(lo, True, hi, True)], ())
    if m := _SINGLE_RE.match(expr):
        v = _clean(m["v"])
        return ("single", [Interval(lo=v, hi=v, hi_inclusive=True)], ())
    if m := _BOUNDS_RE.match(expr):
        return _bounds_clause(m)
    return None


def _maven_clause(expr: str) -> _Clause | None:
    """Interval notation: "[" / "]" inclusive, "(" / ")" exclusive, empty side = unbounded."""
    intervals = []
    for m in _MAVEN_PART_RE.finditer(expr):
        lo, hi = m["lo"] and _clean(m["lo"]), m["hi"] and _clean(m["hi"])
        if m["comma"] is None:  # "[1.2]" is an exact version; "(1.2)" is meaningless
            if lo is None or m["open"] != "[" or m["close"] != "]":
                return None
            intervals.append(Interval(lo, True, lo, True))
            continue
        if lo is None and hi is None:
            return None
        if (lo is None and m["open"] == "[") or (hi is None and m["close"] == "]"):
            return None  # an unbounded side can't be inclusive
        intervals.append(Interval(lo, m["open"] == "[", hi, m["close"] == "]"))
    return ("maven_interval", intervals, ())


def _operator_clause(m: re.Match[str]) -> _Clause | None:
    ops = [(m["op1"], _clean(m["v1"]))]
    if m["op2"]:
        ops.append((m["op2"], _clean(m["v2"])))
    if len(ops) == 1:
        op, v = ops[0]
        if op in ("=", "=="):
            return ("operator", [Interval(lo=v, hi=v, hi_inclusive=True)], ())
        if op.startswith(">"):
            return ("operator", [Interval(lo=v, lo_inclusive=op == ">=")], ())
        return ("operator", [Interval(hi=v, hi_inclusive=op == "<=")], ())
    (op1, v1), (op2, v2) = ops
    if not (op1.startswith(">") and op2.startswith("<")):
        return None
    return ("operator", [Interval(v1, op1 == ">=", v2, op2 == "<=")], ())


def _bounds_clause(m: re.Match[str]) -> _Clause | None:
    comparator, family = _UPPER_KW[m["kw"].lower()]
    if comparator is None:
        return None  # ambiguous keyword
    has_from = m["from"] is not None
    lo_tok = m["lo"]
    if has_from and lo_tok is None:
        return None
    if family == "from_to" and lo_tok is None:
        return None  # bare "to 2.0"
    hi = _clean(m["hi"])
    hi_inclusive = comparator == "<="
    if lo_tok is None:
        return (family, [Interval(hi=hi, hi_inclusive=hi_inclusive)], ())

    lo = _series_bounds(lo_tok)[0] if re.fullmatch(_SERIES, lo_tok) else _clean(lo_tok)
    lo_inclusive = (m["lo_kind"] or "").lower() != "excluding"
    if has_from or family == "from_to":
        family = "from_to"
    elif hi_inclusive:
        family = "a_through_b"
    else:
        family = "branch_before"
    return (family, [Interval(lo, lo_inclusive, hi, hi_inclusive)], ())


def _merge(intervals: list[Interval], scheme: str) -> tuple[Interval, ...] | None:
    """Validate versions, then sort and union the intervals.

    None if any version is invalid for the scheme or any interval is empty ("4.x before 3.1").
    """
    keyed = []
    for iv in intervals:
        lo = parse_version(iv.lo, scheme) if iv.lo is not None else None
        hi = parse_version(iv.hi, scheme) if iv.hi is not None else None
        if (iv.lo is not None and lo is None) or (iv.hi is not None and hi is None):
            return None
        if lo is not None and hi is not None:
            if lo > hi or (lo == hi and not (iv.lo_inclusive and iv.hi_inclusive)):
                return None
        keyed.append((lo, hi, iv))

    # Open lower bounds first; at equal versions an inclusive bound starts earlier.
    keyed.sort(key=lambda k: (False,) if k[0] is None else (True, k[0], not k[2].lo_inclusive))
    merged: list[tuple] = []  # (lo, hi, Interval)
    for lo, hi, iv in keyed:
        if merged:
            plo, phi, piv = merged[-1]
            overlaps = (
                phi is None
                or lo is None
                or lo < phi
                or (lo == phi and (piv.hi_inclusive or iv.lo_inclusive))
            )
            if overlaps:
                if phi is None or (
                    hi is not None and (hi < phi or (hi == phi and piv.hi_inclusive))
                ):
                    continue  # contained in the previous interval
                merged[-1] = (plo, hi, Interval(piv.lo, piv.lo_inclusive, iv.hi, iv.hi_inclusive))
                continue
        merged.append((lo, hi, iv))
    return tuple(m[2] for m in merged)
