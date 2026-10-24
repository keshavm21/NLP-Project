"""LLM extractors (LoRA small model, large-LLM few-shot): prompt building and output parsing.

The model backend is a plain `generate(messages) -> str` callable, so the same extractor serves
a local LoRA model and an API baseline; no client code lives here (decision 9: proprietary
APIs only as baselines). The LLM returns strings, not offsets, so every string is located in the
advisory text to rebuild spans; strings that don't occur in the text are dropped and counted.

By default vers_range comes from the version grammar applied to the located version phrases
(same normalization as the tagger). With use_llm_vers=True the model's own "vers" field is used
instead, if univers accepts it; that is the "no grammar" ablation.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from univers.version_range import VersionRange

from vulntriage.config import load_yaml
from vulntriage.extract.base import Extractor
from vulntriage.extract.version_grammar import combine, parse_version_expr
from vulntriage.schemas import Advisory, AffectedItem, ExtractionResult, Span, SpanLabel
from vulntriage.utils import get_logger

log = get_logger(__name__)

Message = dict[str, str]
Generate = Callable[[list[Message]], str]


def build_messages(
    text: str, prompt: dict[str, Any], n_examples: int | None = None
) -> list[Message]:
    """Chat messages: system, then example user/assistant pairs, then the advisory."""
    template = prompt.get("user_template", "{text}")
    messages = [{"role": "system", "content": prompt["system"].strip()}]
    for ex in prompt.get("examples", [])[:n_examples]:
        messages.append({"role": "user", "content": template.format(text=ex["text"]).strip()})
        messages.append({"role": "assistant", "content": json.dumps(ex["output"])})
    messages.append({"role": "user", "content": template.format(text=text).strip()})
    return messages


def load_json_output(raw: str) -> list[dict[str, Any]] | None:
    """Pull the "affected" list out of a model reply (tolerates code fences and extra prose)."""
    raw = re.sub(r"```(?:json)?", "", raw)
    start = min((i for i in (raw.find("{"), raw.find("[")) if i >= 0), default=-1)
    end = max(raw.rfind("}"), raw.rfind("]"))
    if start < 0 or end < start:
        return None
    try:
        data = json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        return None
    items = data.get("affected") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return None
    return [it for it in items if isinstance(it, dict)]


@dataclass
class ParsedOutput:
    spans: list[Span] = field(default_factory=list)
    affected: list[AffectedItem] = field(default_factory=list)
    unlocated: list[str] = field(default_factory=list)  # strings not found in the text
    valid_json: bool = True


def parse_llm_output(
    text: str, raw: str, scheme: str = "generic", use_llm_vers: bool = False
) -> ParsedOutput:
    """Turn a model reply into spans and AffectedItems grounded in `text`."""
    items = load_json_output(raw)
    if items is None:
        return ParsedOutput(valid_json=False)
    out = ParsedOutput()
    cursor = 0
    for item in items:
        product = _str(item.get("product"))
        if product is None:
            continue
        p_span = _locate(text, product, "PRODUCT", cursor)
        if p_span is None:
            out.unlocated.append(product)
            continue
        cursor = p_span.start

        vendor = _str(item.get("vendor"))
        v_span = _locate(text, vendor, "VENDOR", 0, before=p_span.start) if vendor else None
        if vendor and v_span is None:
            out.unlocated.append(vendor)

        phrases = [p for p in (_str(v) for v in _list(item.get("versions"))) if p]
        version_spans = []
        for phrase in phrases:
            span = _locate(text, phrase, "VERSION_EXPR", p_span.start)
            if span is None:
                out.unlocated.append(phrase)
            else:
                version_spans.append(span)

        fixed = _str(item.get("fixed_version"))
        f_span = None
        if fixed:
            f_span = _locate(text, fixed, "FIXED_VERSION", p_span.start, avoid=version_spans)
            if f_span is None:
                out.unlocated.append(fixed)
        fixed_version = f_span.text if f_span else None

        all_located = len(version_spans) == len(phrases)
        if use_llm_vers:
            vers_range = _valid_vers(_str(item.get("vers")))
        elif not all_located:
            vers_range = None  # a partial range would be a guess
        else:
            vers_range = _grammar_range(version_spans, fixed_version, scheme)

        out.affected.append(
            AffectedItem(
                vendor=v_span,
                product=p_span,
                version_spans=version_spans,
                vers_range=vers_range,
                fixed_version=fixed_version,
            )
        )
        out.spans.extend(s for s in (v_span, p_span, *version_spans, f_span) if s is not None)
    out.spans = sorted(_unique(out.spans), key=lambda s: (s.start, s.end, s.label))
    return out


class LLMExtractor(Extractor):
    """Prompted LLM -> JSON -> grounded spans. `generate` is the model backend."""

    def __init__(
        self,
        generate: Generate,
        prompt: dict[str, Any] | str | Path = "configs/extract/prompts/few_shot.yaml",
        name: str = "llm",
        scheme: str = "generic",
        n_examples: int | None = None,
        use_llm_vers: bool = False,
    ) -> None:
        self.generate = generate
        self.prompt = prompt if isinstance(prompt, dict) else load_yaml(prompt)
        self.name = name
        self.scheme = scheme
        self.n_examples = n_examples
        self.use_llm_vers = use_llm_vers

    def extract(self, advisory: Advisory) -> ExtractionResult:
        raw = self.generate(build_messages(advisory.text, self.prompt, self.n_examples))
        parsed = parse_llm_output(advisory.text, raw, self.scheme, self.use_llm_vers)
        if not parsed.valid_json:
            log.warning("%s: invalid JSON from %s", advisory.id, self.name)
        if parsed.unlocated:
            log.info(
                "%s: %d strings not in text: %s",
                advisory.id,
                len(parsed.unlocated),
                parsed.unlocated,
            )
        return ExtractionResult(
            advisory_id=advisory.id, spans=parsed.spans, affected=parsed.affected, model=self.name
        )


# --- helpers ----------------------------------------------------------------------------------


def _str(value: Any) -> str | None:
    return (value.strip() or None) if isinstance(value, str) else None


def _list(value: Any) -> list:
    if isinstance(value, list):
        return value
    return [value] if isinstance(value, str) else []


def _occurrences(text: str, needle: str) -> list[int]:
    """Start offsets of `needle` in `text` at word boundaries; exact case first, then any case."""
    for flags in (0, re.I):
        pattern = re.compile(rf"(?<!\w){re.escape(needle)}(?!\w)", flags)
        found = [m.start() for m in pattern.finditer(text)]
        if found:
            return found
    return []


def _locate(
    text: str,
    needle: str,
    label: SpanLabel,
    after: int,
    before: int | None = None,
    avoid: list[Span] | tuple[()] = (),
) -> Span | None:
    """Find `needle` in `text`. Prefers the first occurrence at/after `after` that doesn't overlap
    `avoid`; `before` restricts to occurrences ending by that offset (nearest one wins)."""
    starts = _occurrences(text, needle)
    if before is not None:
        starts = [s for s in starts if s + len(needle) <= before][-1:]

    def free(s: int) -> bool:
        return not any(s < a.end and a.start < s + len(needle) for a in avoid)

    ranked = (
        [s for s in starts if s >= after and free(s)]
        + [s for s in starts if free(s)]
        + [s for s in starts if s >= after]
        + starts
    )
    if not ranked:
        return None
    return Span.from_text(text, ranked[0], ranked[0] + len(needle), label)


def _unique(spans: list[Span]) -> list[Span]:
    seen, out = set(), []
    for s in spans:
        key = (s.start, s.end, s.label)
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out


def _grammar_range(version_spans: list[Span], fixed: str | None, scheme: str) -> str | None:
    if version_spans:
        parse = combine([parse_version_expr(s.text, scheme) for s in version_spans])
    elif fixed:
        parse = parse_version_expr(f"fixed in {fixed}", scheme)
    else:
        return None
    return None if parse is None else parse.vers


def _valid_vers(vers: str | None) -> str | None:
    if not vers:
        return None
    try:
        return str(VersionRange.from_string(vers))
    except Exception:  # univers raises various errors on malformed ranges
        return None
