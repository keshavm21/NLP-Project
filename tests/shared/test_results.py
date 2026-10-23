import json

import pytest

from vulntriage.eval import load_results, write_result


def test_write_and_load_result(tmp_path):
    path = write_result(
        component="cwe",
        system="TF-IDF + LR",
        split="dev",
        n=10,
        metrics={"accuracy": 0.5},
        seed=42,
        results_dir=tmp_path,
    )
    data = json.loads(path.read_text())
    assert data["run_id"].startswith("cwe_tf-idf-lr_")
    assert data["run_id"].endswith("_s42")
    assert [r.metrics for r in load_results("cwe", results_dir=tmp_path)] == [{"accuracy": 0.5}]


def test_rejects_unknown_component(tmp_path):
    with pytest.raises(ValueError):
        write_result(
            component="cwes", system="x", split="dev", n=1, metrics={}, seed=0, results_dir=tmp_path
        )
