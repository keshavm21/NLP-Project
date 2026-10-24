"""BIO span tagger (DeBERTa-v3) — skeleton: label mapping, offset mapping, inference wrapper.

Training is not written yet (needs P1's silver spans). What is here:
  - BIO label <-> id maps over SPAN_LABELS.
  - spans_to_token_labels: character spans -> one label id per subword token (for training).
  - token_labels_to_spans: per-token label ids -> character spans (for inference).
  - token_windows / merge_window_predictions: advisories longer than max_length are tagged in
    overlapping windows; each token keeps the prediction from the window where it has the most
    context.
  - DebertaTagger(Extractor): tokenizer + predict function -> spans -> grouping. Both can be
    injected (tests use a stub); otherwise they are loaded lazily from a model directory.

Offsets come from a fast tokenizer's `offset_mapping`: one (start, end) per token, (0, 0) for
special tokens. SentencePiece tokens may include the leading space ("▁before" -> " before"),
so token starts are moved past whitespace before alignment.
torch/transformers are imported only inside DebertaTagger._load, so core installs work.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

from vulntriage.extract.base import Extractor
from vulntriage.extract.grouping import group_affected
from vulntriage.schemas import SPAN_LABELS, Advisory, ExtractionResult, Span

IGNORE_INDEX = -100  # ignored by the cross-entropy loss (special tokens, non-first subwords)
BIO_LABELS: tuple[str, ...] = ("O",) + tuple(f"{p}-{lab}" for lab in SPAN_LABELS for p in "BI")
LABEL2ID: dict[str, int] = {lab: i for i, lab in enumerate(BIO_LABELS)}
ID2LABEL: dict[int, str] = dict(enumerate(BIO_LABELS))

Offsets = Sequence[tuple[int, int]]


def _trim(text: str, start: int, end: int, punct: bool = False) -> tuple[int, int]:
    """Shrink [start, end) so it doesn't begin or end with whitespace (or, with `punct`, with
    brackets/quotes/sentence punctuation, which no span label ends or starts with)."""
    lead = " \t\n\r" + ("([{\"'" if punct else "")
    tail = " \t\n\r" + (".,;:)]}\"'" if punct else "")
    while start < end and text[start] in lead:
        start += 1
    while end > start and text[end - 1] in tail:
        end -= 1
    return start, end


def _is_special(offset: tuple[int, int]) -> bool:
    return offset[0] == offset[1]


def spans_to_token_labels(
    text: str,
    offsets: Offsets,
    spans: Sequence[Span],
    label_all_subtokens: bool = True,
) -> list[int]:
    """Character spans -> BIO label id per token.

    A token belongs to a span if their (whitespace-trimmed) character ranges overlap; the first
    such token gets B-, the rest I-. Special tokens get IGNORE_INDEX; so do non-first subwords of
    a word when `label_all_subtokens` is False. Overlapping spans: the earlier one wins.
    """
    labels = [LABEL2ID["O"]] * len(offsets)
    taken = [False] * len(offsets)
    for span in sorted(spans, key=lambda s: (s.start, -s.end)):
        first = True
        for i, off in enumerate(offsets):
            if _is_special(off) or taken[i]:
                continue
            start, end = _trim(text, *off)
            if start < span.end and end > span.start:
                labels[i] = LABEL2ID[f"{'B' if first else 'I'}-{span.label}"]
                taken[i] = True
                first = False
    for i, off in enumerate(offsets):
        if _is_special(off):
            labels[i] = IGNORE_INDEX
        elif not label_all_subtokens and i > 0 and _continues_word(text, offsets, i):
            labels[i] = IGNORE_INDEX
    return labels


def _continues_word(text: str, offsets: Offsets, i: int) -> bool:
    """True if token i is a non-first subword (glued to the previous token, no space between)."""
    prev = offsets[i - 1]
    if _is_special(prev):
        return False
    start = offsets[i][0]
    return prev[1] == start and start < len(text) and not text[start].isspace()


def token_labels_to_spans(text: str, offsets: Offsets, label_ids: Sequence[int]) -> list[Span]:
    """Per-token BIO label ids -> character spans over `text`.

    Lenient decoding: an I- tag that doesn't continue a span of the same type starts a new one.
    Special tokens end the current span; IGNORE_INDEX tokens (non-first subwords) extend it.
    With first-subtoken-only labels a span covers whole words ("2.4.3)" in "(fixed in 2.4.3)"),
    so surrounding brackets/punctuation are trimmed from decoded spans.
    """
    spans: list[Span] = []
    cur: list | None = None  # [label, start, end]

    def close() -> None:
        nonlocal cur
        if cur is not None:
            start, end = _trim(text, cur[1], cur[2], punct=True)
            if end > start:
                spans.append(Span.from_text(text, start, end, cur[0]))
        cur = None

    for off, lid in zip(offsets, label_ids, strict=True):
        if _is_special(off):
            close()
            continue
        if lid == IGNORE_INDEX:
            if cur is not None:
                cur[2] = max(cur[2], off[1])
            continue
        tag = ID2LABEL[lid]
        if tag == "O":
            close()
            continue
        prefix, label = tag.split("-", 1)
        if prefix == "B" or cur is None or cur[0] != label:
            close()
            cur = [label, off[0], off[1]]
        else:
            cur[2] = off[1]
    close()
    return spans


def token_windows(n_tokens: int, size: int, stride: int) -> list[tuple[int, int]]:
    """[start, end) windows of at most `size` tokens; consecutive windows overlap by `stride`."""
    if size <= 0 or not 0 <= stride < size:
        raise ValueError(f"need 0 <= stride < size, got size={size}, stride={stride}")
    if n_tokens <= size:
        return [(0, n_tokens)]
    out, start = [], 0
    while True:
        end = min(start + size, n_tokens)
        out.append((start, end))
        if end == n_tokens:
            return out
        start += size - stride


def merge_window_predictions(
    n_tokens: int, windows: list[tuple[int, int]], preds: list[list[int]]
) -> list[int]:
    """One label per token: from the window where the token has the most context on both sides."""
    merged = [IGNORE_INDEX] * n_tokens
    best = [-1] * n_tokens
    for (start, end), labels in zip(windows, preds, strict=True):
        for i in range(start, end):
            context = min(i - start, end - 1 - i)
            if context > best[i]:
                best[i], merged[i] = context, labels[i - start]
    return merged


Predict = Callable[[dict], list[int]]


class DebertaTagger(Extractor):
    """Token-classification extractor: tagger spans + rule-based grouping + version grammar."""

    name = "deberta-tagger"

    def __init__(
        self,
        model_dir: str | Path | None = None,
        scheme: str = "generic",
        max_length: int = 512,
        stride: int = 128,
        tokenizer=None,
        predict: Predict | None = None,
    ) -> None:
        self.model_dir = model_dir
        self.scheme = scheme
        self.max_length = max_length
        self.stride = stride
        self.tokenizer = tokenizer
        self.predict = predict

    def extract(self, advisory: Advisory) -> ExtractionResult:
        if self.tokenizer is None or self.predict is None:
            self._load()
        text = advisory.text
        offsets, labels = self._tag(text)
        spans = token_labels_to_spans(text, offsets, labels)
        return ExtractionResult(
            advisory_id=advisory.id,
            spans=spans,
            affected=group_affected(text, spans, self.scheme),
            model=self.name,
        )

    def _tag(self, text: str) -> tuple[list[tuple[int, int]], list[int]]:
        """Tokenize the whole text, predict over overlapping windows, merge per token."""
        enc = self.tokenizer(
            text, return_offsets_mapping=True, add_special_tokens=False, truncation=False
        )
        ids = list(enc["input_ids"])
        offsets = [tuple(o) for o in enc["offset_mapping"]]
        cls, sep = self.tokenizer.cls_token_id, self.tokenizer.sep_token_id
        windows = token_windows(len(ids), self.max_length - 2, self.stride)
        preds = []
        for start, end in windows:
            window = {
                "input_ids": [cls, *ids[start:end], sep],
                "attention_mask": [1] * (end - start + 2),
                "offset_mapping": [(0, 0), *offsets[start:end], (0, 0)],
            }
            preds.append(self.predict(window)[1:-1])  # drop [CLS]/[SEP] predictions
        return offsets, merge_window_predictions(len(ids), windows, preds)

    def _load(self) -> None:
        """Load a fine-tuned model from `model_dir` (needs the `ml` extra)."""
        if self.model_dir is None:
            raise ValueError("DebertaTagger needs model_dir, or both tokenizer and predict")
        import torch
        from transformers import AutoModelForTokenClassification, AutoTokenizer

        tokenizer = AutoTokenizer.from_pretrained(self.model_dir)
        model = AutoModelForTokenClassification.from_pretrained(self.model_dir).eval()

        def predict(enc: dict) -> list[int]:
            inputs = {k: torch.tensor([enc[k]]) for k in ("input_ids", "attention_mask")}
            with torch.no_grad():
                logits = model(**inputs).logits[0]
            return logits.argmax(-1).tolist()

        self.tokenizer = self.tokenizer or tokenizer
        self.predict = self.predict or predict
