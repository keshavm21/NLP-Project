"""Tests for cross-source deduplication (P1)."""

from datetime import datetime, timezone

from vulntriage.ingest.dedup import deduplicate
from vulntriage.schemas import Advisory


def _make_adv(
    adv_id: str,
    source: str,
    aliases: list[str],
    text: str = "A vulnerability in library foo.",
    refs: list[str] | None = None,
    pub_year: int = 2024,
) -> Advisory:
    return Advisory(
        id=adv_id,
        aliases=aliases,
        source=source,
        published=datetime(pub_year, 1, 15, tzinfo=timezone.utc),
        text=text,
        references=refs or [],
    )


def test_dedup_empty_and_single():
    assert deduplicate([]) == []
    adv = _make_adv("CVE-2024-0001", "nvd", [])
    res = deduplicate([adv])
    assert len(res) == 1
    assert res[0].id == "CVE-2024-0001"


def test_dedup_merges_by_shared_alias():
    # Advisory 1 from GHSA has alias CVE-2024-1111
    # Advisory 2 from NVD has id CVE-2024-1111
    a1 = _make_adv("GHSA-1111-2222-3333", "ghsa", ["CVE-2024-1111"], refs=["https://ghsa.com"])
    a2 = _make_adv("CVE-2024-1111", "nvd", [], refs=["https://nvd.nist.gov"])

    res = deduplicate([a1, a2])
    assert len(res) == 1
    merged = res[0]
    # NVD is prioritized over GHSA
    assert merged.id == "CVE-2024-1111"
    assert merged.source == "nvd"
    # Merged aliases contain the GHSA id
    assert "GHSA-1111-2222-3333" in merged.aliases
    # Merged references contain both URLs
    assert set(merged.references) == {"https://ghsa.com", "https://nvd.nist.gov"}


def test_dedup_source_priority():
    # NVD > CVE5 > Vulnrichment > GHSA > OSV > Bulletin
    a_vuln = _make_adv("CVE-2024-2222", "vulnrichment", ["CVE-2024-2222"])
    a_cve5 = _make_adv("CVE-2024-2222", "cve5", ["CVE-2024-2222"])
    a_nvd = _make_adv("CVE-2024-2222", "nvd", ["CVE-2024-2222"])

    res = deduplicate([a_vuln, a_cve5, a_nvd])
    assert len(res) == 1
    assert res[0].source == "nvd"

    # Test without NVD: CVE5 should win
    res2 = deduplicate([a_vuln, a_cve5])
    assert len(res2) == 1
    assert res2[0].source == "cve5"


def test_dedup_transitive_alias_chain():
    # A shares alias with B, B shares alias with C -> all 3 merged
    a = _make_adv("GHSA-aaaa-bbbb-cccc", "ghsa", ["CVE-2024-3333"])
    b = _make_adv("CVE-2024-3333", "cve5", ["GHSA-xxxx-yyyy-zzzz"])
    c = _make_adv("OSV-2024-9999", "osv", ["GHSA-xxxx-yyyy-zzzz"])

    res = deduplicate([a, b, c])
    assert len(res) == 1
    merged = res[0]
    assert merged.id == "CVE-2024-3333"
    assert set(merged.aliases) >= {"GHSA-aaaa-bbbb-cccc", "GHSA-xxxx-yyyy-zzzz", "OSV-2024-9999"}


def test_dedup_text_similarity_fallback_for_bulletins():
    text1 = (
        "Red Hat Security Advisory: critical buffer overflow in OpenSSL crypto library "
        "leading to RCE."
    )
    text2 = (
        "Red Hat Security Advisory: critical buffer overflow in OpenSSL crypto library "
        "leading to RCE."
    )
    b1 = _make_adv("RHSA-2024-001", "bulletin", [], text=text1, pub_year=2024)
    b2 = _make_adv("RHSA-2024-002", "bulletin", [], text=text2, pub_year=2024)

    res = deduplicate([b1, b2])
    assert len(res) == 1
    assert "RHSA-2024-002" in res[0].aliases or res[0].id == "RHSA-2024-002"


def test_dedup_disjoint_advisories():
    a1 = _make_adv("CVE-2024-0001", "nvd", [])
    a2 = _make_adv("CVE-2024-0002", "nvd", [])
    res = deduplicate([a1, a2])
    assert len(res) == 2
