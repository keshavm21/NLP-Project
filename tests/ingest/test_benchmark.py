"""Tests for benchmark building orchestration (P1)."""

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from vulntriage.ingest.benchmark import main as benchmark_main
from vulntriage.schemas import Advisory


def test_benchmark_cli_help():
    with patch("sys.argv", ["benchmark", "--help"]):
        import pytest

        with pytest.raises(SystemExit) as exc:
            benchmark_main(["--help"])
        assert exc.value.code == 0


def test_benchmark_validate_gold_cli():
    # Test --validate-gold command
    ret = benchmark_main(["--validate-gold"])
    assert ret == 0


def test_benchmark_pipeline_execution(tmp_path: Path):
    # Mock data sources to produce sample advisories across splits
    adv_train = Advisory(
        id="CVE-2024-0001",
        source="nvd",
        published=datetime(2024, 5, 1, tzinfo=timezone.utc),
        text="Vulnerability in requests before 2.32.0 allows certificate bypass.",
    )
    adv_dev = Advisory(
        id="CVE-2025-0002",
        source="ghsa",
        published=datetime(2025, 2, 1, tzinfo=timezone.utc),
        text="Vulnerability in flask before 3.0.1.",
    )
    adv_test = Advisory(
        id="CVE-2025-0003",
        source="cve5",
        published=datetime(2025, 7, 10, tzinfo=timezone.utc),
        text="Vulnerability in struts before 2.5.33.",
    )

    from vulntriage.config import Paths

    # Create dummy split config in tmp_path
    (tmp_path / "configs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "configs" / "splits.yaml").write_text(
        "snapshot_date: '2026-10-25'\ntrain:\n  end: '2024-12-31'\ndev:\n  start: '2025-01-01'\n  end: '2025-06-30'\ntest:\n  start: '2025-07-01'\n",
        encoding="utf-8",
    )

    with (
        patch("vulntriage.ingest.benchmark.get_paths", return_value=Paths(tmp_path)),
        patch(
            "vulntriage.ingest.benchmark.iter_all_advisories",
            return_value=[adv_train, adv_dev, adv_test],
        ),
        # Isolate from real (potentially corrupt) KEV file on disk
        patch(
            "vulntriage.ingest.sources.kev.KEVSource.load_kev_set",
            return_value={"CVE-2024-0001"},
        ),
    ):
        ret = benchmark_main(["--limit", "10"])
        assert ret == 0
        assert (tmp_path / "data" / "processed" / "train.jsonl").exists()
        assert (tmp_path / "results" / "ingest" / "stats_v0.json").exists()

