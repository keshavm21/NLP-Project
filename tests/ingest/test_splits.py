"""Tests for temporal dataset splitting and leakage prevention (P1)."""

from datetime import date, datetime, timezone

import pytest

from vulntriage.config import SplitConfig, load_splits
from vulntriage.schemas import Advisory


def test_split_config_ordering():
    split_cfg = load_splits("configs/splits.yaml")
    assert split_cfg.train_end < split_cfg.dev_start
    assert split_cfg.dev_start <= split_cfg.dev_end
    assert split_cfg.dev_end < split_cfg.test_start


def test_temporal_split_assignments():
    split_cfg = load_splits("configs/splits.yaml")

    # Train window: <= 2024-12-31
    assert split_cfg.assign(date(2020, 1, 1)) == "train"
    assert split_cfg.assign(datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)) == "train"
    assert split_cfg.usable_for_training(date(2024, 12, 31)) is True

    # Dev window: 2025-01-01 to 2025-06-30
    assert split_cfg.assign(date(2025, 1, 1)) == "dev"
    assert split_cfg.assign(date(2025, 3, 15)) == "dev"
    assert split_cfg.assign(date(2025, 6, 30)) == "dev"
    assert split_cfg.usable_for_training(date(2025, 1, 1)) is False

    # Test window: 2025-07-01 to snapshot
    assert split_cfg.assign(date(2025, 7, 1)) == "test"
    assert split_cfg.assign(date(2025, 8, 15)) == "test"
    assert split_cfg.usable_for_training(date(2025, 7, 1)) is False


def test_split_config_rejects_overlapping_windows():
    with pytest.raises(ValueError, match="windows overlap or are out of order"):
        SplitConfig(
            train_end=date(2025, 1, 1),
            dev_start=date(2024, 12, 1),  # starts before train ends!
            dev_end=date(2025, 6, 1),
            test_start=date(2025, 7, 1),
            snapshot=None,
        )


def test_no_temporal_leakage_in_advisory_split():
    split_cfg = load_splits("configs/splits.yaml")

    train_adv = Advisory(
        id="CVE-2024-0001",
        source="nvd",
        published=datetime(2024, 6, 1, tzinfo=timezone.utc),
        text="Sample text",
        split=split_cfg.assign(datetime(2024, 6, 1, tzinfo=timezone.utc)),
    )
    test_adv = Advisory(
        id="CVE-2025-0001",
        source="nvd",
        published=datetime(2025, 7, 15, tzinfo=timezone.utc),
        text="Sample text",
        split=split_cfg.assign(datetime(2025, 7, 15, tzinfo=timezone.utc)),
    )

    assert train_adv.split == "train"
    assert test_adv.split == "test"
    assert split_cfg.usable_for_training(train_adv.published) is True
    assert split_cfg.usable_for_training(test_adv.published) is False
