from datetime import date

from vulntriage.config import SplitConfig, get_paths, load_splits


def test_repo_paths_exist():
    paths = get_paths()
    assert (paths.root / "pyproject.toml").exists()
    assert paths.configs.exists()


def test_splits_load_and_are_ordered():
    split = load_splits()
    assert split.train_end < split.dev_start <= split.dev_end < split.test_start


def test_split_assignment_boundaries():
    s = SplitConfig(
        train_end=date(2024, 12, 31),
        dev_start=date(2025, 1, 1),
        dev_end=date(2025, 6, 30),
        test_start=date(2025, 7, 1),
        snapshot=date(2026, 10, 1),
    )
    assert s.assign(date(2024, 12, 31)) == "train"
    assert s.assign(date(2025, 1, 1)) == "dev"
    assert s.assign(date(2025, 6, 30)) == "dev"
    assert s.assign(date(2025, 7, 1)) == "test"
    assert s.assign(date(2026, 10, 2)) is None  # after snapshot
    assert not s.usable_for_training(date(2025, 3, 1))
