"""Tests for data source downloaders and parsers (P1)."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from vulntriage.ingest.download import ALL_SOURCES
from vulntriage.ingest.download import main as download_main
from vulntriage.ingest.sources.bulletin import _parse_bulletin
from vulntriage.ingest.sources.cve5 import _parse_cve5_file
from vulntriage.ingest.sources.ghsa import _parse_ghsa
from vulntriage.ingest.sources.kev import KEVSource
from vulntriage.ingest.sources.nvd import _parse_cve
from vulntriage.ingest.sources.osv import _parse_osv
from vulntriage.ingest.sources.vulnrichment import _parse_vulnrichment


def test_all_sources_registered():
    expected = {
        "nvd",
        "cve5",
        "vulnrichment",
        "ghsa",
        "osv",
        "kev",
        "epss",
        "cpe",
        "cwe",
        "bulletin",
    }
    assert set(ALL_SOURCES.keys()) == expected
    for name, cls in ALL_SOURCES.items():
        assert cls.name == name


# --- NVD Parser ---


def test_nvd_parse_valid_cve():
    cve_data = {
        "id": "CVE-2024-1234",
        "published": "2024-05-01T12:00:00.000",
        "lastModified": "2024-05-02T12:00:00.000",
        "descriptions": [{"lang": "en", "value": "A remote code execution flaw in libfoo."}],
        "weaknesses": [{"description": [{"value": "CWE-89"}, {"value": "NVD-CWE-noinfo"}]}],
        "references": [{"url": "https://example.com/cve"}],
    }
    adv = _parse_cve(cve_data)
    assert adv is not None
    assert adv.id == "CVE-2024-1234"
    assert adv.source == "nvd"
    assert adv.published == datetime(2024, 5, 1, 12, 0, tzinfo=timezone.utc)
    assert "cwe:CWE-89" in adv.aliases
    assert "cwe:NVD-CWE-noinfo" not in adv.aliases  # placeholder dropped
    assert adv.references == ["https://example.com/cve"]


def test_nvd_parse_invalid_cve():
    assert _parse_cve({"id": "NOT-CVE"}) is None
    assert _parse_cve({"id": "CVE-2024-1", "published": None}) is None
    assert (
        _parse_cve({"id": "CVE-2024-1", "published": "2024-01-01T00:00:00", "descriptions": []})
        is None
    )


# --- GHSA Parser ---


def test_ghsa_parse_valid(tmp_path: Path):
    record = {
        "id": "GHSA-1234-5678-90ab",
        "published": "2024-03-15T10:00:00Z",
        "summary": "SQL injection in flask-app",
        "details": "Details on SQL injection vulnerability.",
        "aliases": ["CVE-2024-9999"],
        "affected": [{"package": {"ecosystem": "PyPI", "name": "flask-app"}}],
        "database_specific": {"cwe_ids": ["CWE-89"]},
        "references": [{"url": "https://github.com/advisories/GHSA-1234-5678-90ab"}],
    }
    f = tmp_path / "ghsa.json"
    f.write_text(json.dumps(record), encoding="utf-8")

    adv = _parse_ghsa(f)
    assert adv is not None
    assert adv.id == "CVE-2024-9999"  # CVE canonical
    assert "GHSA-1234-5678-90ab" in adv.aliases
    assert adv.source == "ghsa"
    assert adv.published == datetime(2024, 3, 15, 10, 0, tzinfo=timezone.utc)


def test_ghsa_skips_non_target_ecosystem(tmp_path: Path):
    record = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "published": "2024-03-15T10:00:00Z",
        "details": "Some vuln in Go.",
        "affected": [{"package": {"ecosystem": "Go", "name": "golang.org/x/crypto"}}],
    }
    f = tmp_path / "go_ghsa.json"
    f.write_text(json.dumps(record), encoding="utf-8")
    assert _parse_ghsa(f) is None


# --- OSV Parser ---


def test_osv_parse_valid():
    record = {
        "id": "OSV-2024-5555",
        "published": "2024-02-10T08:30:00Z",
        "summary": "Prototype pollution in lodash",
        "aliases": ["GHSA-xxxx-yyyy-zzzz", "CVE-2024-3333"],
        "database_specific": {"cwe_ids": ["CWE-1321"]},
        "references": [{"url": "https://example.com/osv"}],
    }
    adv = _parse_osv(record)
    assert adv is not None
    assert adv.id == "CVE-2024-3333"  # Prefer CVE ID
    assert "OSV-2024-5555" in adv.aliases
    assert "GHSA-xxxx-yyyy-zzzz" in adv.aliases


# --- CVE5 Parser ---


def test_cve5_parse_valid(tmp_path: Path):
    record = {
        "cveMetadata": {
            "cveId": "CVE-2024-5000",
            "datePublished": "2024-04-01T00:00:00Z",
            "dateUpdated": "2024-04-02T00:00:00Z",
        },
        "containers": {
            "cna": {
                "title": "Buffer overflow in demo-lib",
                "descriptions": [
                    {"lang": "en", "value": "A buffer overflow in demo-lib allows DoS."}
                ],
                "problemTypes": [{"descriptions": [{"cweId": "CWE-120"}]}],
                "references": [{"url": "https://cve.org/cve5"}],
            }
        },
    }
    f = tmp_path / "CVE-2024-5000.json"
    f.write_text(json.dumps(record), encoding="utf-8")

    adv = _parse_cve5_file(f)
    assert adv is not None
    assert adv.id == "CVE-2024-5000"
    assert adv.source == "cve5"
    assert "cwe:CWE-120" in adv.aliases


# --- Vulnrichment Parser ---


def test_vulnrichment_parse_valid(tmp_path: Path):
    record = {
        "cveMetadata": {
            "cveId": "CVE-2024-6000",
            "datePublished": "2024-06-01T00:00:00Z",
        },
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "CNA description text."}],
            },
            "adp": [{"problemTypes": [{"descriptions": [{"cweId": "CWE-79"}]}]}],
        },
    }
    f = tmp_path / "CVE-2024-6000.json"
    f.write_text(json.dumps(record), encoding="utf-8")

    adv = _parse_vulnrichment(f)
    assert adv is not None
    assert adv.id == "CVE-2024-6000"
    assert adv.source == "vulnrichment"
    assert "cwe:CWE-79" in adv.aliases


# --- Bulletin Parser ---


def test_bulletin_parse():
    rec = {
        "id": "RHSA-2024-1111",
        "published": "2024-07-01",
        "text": "Red Hat advisory for openssl.",
        "aliases": ["CVE-2024-9999"],
        "references": ["https://access.redhat.com/errata/RHSA-2024-1111"],
    }
    adv = _parse_bulletin(rec)
    assert adv is not None
    assert adv.id == "RHSA-2024-1111"
    assert adv.source == "bulletin"
    assert adv.aliases == ["CVE-2024-9999"]


# --- KEV and EPSS ---


def test_kev_load(tmp_path: Path):
    kev_src = KEVSource()
    kev_file = tmp_path / "known_exploited_vulnerabilities.json"
    kev_file.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j"}
                ]
            }
        )
    )
    with patch.object(KEVSource, "raw_dir", new_callable=lambda: tmp_path):
        kev_set = kev_src.load_kev_set()
        assert "CVE-2021-44228" in kev_set
        assert len(kev_src.load_kev_records()) == 1


# --- Download CLI ---


def test_download_cli_unknown_source():
    assert download_main(["--sources", "nonexistent"]) == 1
