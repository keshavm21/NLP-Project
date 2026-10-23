"""Glue that runs the whole system: advisory text -> ranked patch queue.

Every component is passed in, so any implementation (baseline, main model, or a
gold-label stand-in) can be swapped without changing this file. Used by the API,
the end-to-end replay (P5) and the RQ4 comparison.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from vulntriage.classify.base import Classifier
from vulntriage.extract.base import Extractor
from vulntriage.linking.base import Linker
from vulntriage.match.base import Matcher
from vulntriage.rank.base import Ranker
from vulntriage.schemas import SBOM, Advisory, ExtractionResult, Match, Prediction, QueueItem


@dataclass
class PipelineOutput:
    queue: list[QueueItem]
    extractions: dict[str, ExtractionResult] = field(default_factory=dict)
    predictions: dict[str, Prediction] = field(default_factory=dict)
    matches: list[Match] = field(default_factory=list)


@dataclass
class Pipeline:
    extractor: Extractor
    linker: Linker
    classifier: Classifier
    matcher: Matcher
    ranker: Ranker

    def run(self, advisories: Iterable[Advisory], sboms: Iterable[SBOM]) -> PipelineOutput:
        sbom_map = {s.id: s for s in sboms}
        out = PipelineOutput(queue=[])
        for adv in advisories:
            ext = self.extractor.extract(adv)
            out.extractions[adv.id] = ext
            out.predictions[adv.id] = self.classifier.predict(adv)
            pairs = [(self.linker.link(item.product, adv), item) for item in ext.affected]
            if not pairs:
                continue
            for sbom in sbom_map.values():
                out.matches.extend(self.matcher.match(adv.id, pairs, sbom))
        affected = [m for m in out.matches if m.affected]
        out.queue = self.ranker.rank(affected, out.predictions, out.extractions, sbom_map)
        return out
