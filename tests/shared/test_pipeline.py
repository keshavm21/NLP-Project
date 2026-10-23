"""Runs the full pipeline with tiny fake components.

Also serves as a worked example of how each member's component plugs in.
"""

from vulntriage.classify.base import Classifier
from vulntriage.extract.base import Extractor
from vulntriage.linking.base import Linker
from vulntriage.match.base import Matcher
from vulntriage.pipeline import Pipeline
from vulntriage.rank.base import Ranker
from vulntriage.schemas import (
    SBOM,
    AffectedItem,
    ExtractionResult,
    LinkedProduct,
    Match,
    Prediction,
    QueueItem,
    SBOMComponent,
    Span,
)


class FakeExtractor(Extractor):
    name = "fake"

    def extract(self, advisory):
        t = advisory.text
        prod = Span.from_text(t, t.index("libfoo"), t.index("libfoo") + 6, "PRODUCT")
        ver_start = t.index("before 2.4.3")
        ver = Span.from_text(t, ver_start, ver_start + len("before 2.4.3"), "VERSION_EXPR")
        item = AffectedItem(
            product=prod, version_spans=[ver], vers_range="vers:pypi/<2.4.3", fixed_version="2.4.3"
        )
        return ExtractionResult(
            advisory_id=advisory.id, spans=[prod, ver], affected=[item], model=self.name
        )


class FakeLinker(Linker):
    name = "fake"

    def link(self, mention, advisory):
        return LinkedProduct(
            mention=mention,
            identifier="pkg:pypi/libfoo",
            score=0.9,
            candidates=[("pkg:pypi/libfoo", 0.9)],
        )


class FakeClassifier(Classifier):
    name = "fake"

    def predict(self, advisory):
        return Prediction(advisory_id=advisory.id, cwe=[("CWE-787", 0.8)], cvss_base_score=9.8)


class FakeMatcher(Matcher):
    def match(self, advisory_id, affected, sbom):
        out = []
        for linked, item in affected:
            for c in sbom.components:
                if c.purl and c.purl.split("@")[0] == linked.identifier:
                    out.append(
                        Match(
                            advisory_id=advisory_id,
                            sbom_id=sbom.id,
                            component_purl=c.purl,
                            component_version=c.version,
                            affected=c.version < "2.4.3",
                            vers_range=item.vers_range,
                        )
                    )
        return out


class FakeRanker(Ranker):
    def rank(self, matches, predictions, extractions, sboms):
        items = [
            QueueItem(
                advisory_id=m.advisory_id,
                sbom_id=m.sbom_id,
                component_purl=m.component_purl,
                risk_score=predictions[m.advisory_id].cvss_base_score or 0.0,
                needs_review=False,
                recommended_version="2.4.3",
                evidence=extractions[m.advisory_id].spans,
            )
            for m in matches
        ]
        return sorted(items, key=lambda q: q.risk_score, reverse=True)


def test_pipeline_end_to_end(advisory):
    sboms = [
        SBOM(
            id="app-a",
            components=[
                SBOMComponent(purl="pkg:pypi/libfoo@2.4.1", name="libfoo", version="2.4.1")
            ],
        ),
        SBOM(
            id="app-b",
            components=[
                SBOMComponent(purl="pkg:pypi/libfoo@2.5.0", name="libfoo", version="2.5.0")
            ],
        ),
    ]
    pipe = Pipeline(FakeExtractor(), FakeLinker(), FakeClassifier(), FakeMatcher(), FakeRanker())
    out = pipe.run([advisory], sboms)
    assert [q.sbom_id for q in out.queue] == ["app-a"]  # only the affected project
    assert out.queue[0].recommended_version == "2.4.3"
