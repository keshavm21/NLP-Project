import pytest

from vulntriage.eval import metrics as m


def test_span_prf_micro_and_per_label():
    gold = [[(0, 6, "PRODUCT"), (7, 13, "VERSION_EXPR")]]
    pred = [[(0, 6, "PRODUCT"), (7, 12, "VERSION_EXPR")]]
    out = m.span_prf(gold, pred)
    assert out["PRODUCT_f1"] == 1.0
    assert out["VERSION_EXPR_f1"] == 0.0
    assert out["precision"] == 0.5 and out["recall"] == 0.5


def test_classification_metrics():
    gold = ["a", "a", "b", "c"]
    pred = ["a", "b", "b", "c"]
    assert m.accuracy(gold, pred) == 0.75
    assert 0 < m.macro_f1(gold, pred) < 1
    assert m.top_k_accuracy(["a"], [["b", "a"]], k=1) == 0.0
    assert m.top_k_accuracy(["a"], [["b", "a"]], k=2) == 1.0


def test_ece_perfectly_calibrated_is_zero():
    assert m.expected_calibration_error([1.0, 1.0], [True, True]) == pytest.approx(0.0)
    assert m.expected_calibration_error([0.9, 0.9], [False, False]) == pytest.approx(0.9)


def test_linking_metrics():
    gold = ["pkg:pypi/a", None, "pkg:npm/b"]
    ranked = [["pkg:pypi/a"], [], ["x", "pkg:npm/b"]]
    assert m.recall_at_k(gold, ranked, k=1) == 0.5
    assert m.nil_prf(gold, ["pkg:pypi/a", None, None])["nil_precision"] == 0.5


def test_ndcg():
    assert m.ndcg_at_k([3, 2, 1], k=3) == pytest.approx(1.0)
    assert m.ndcg_at_k([1, 2, 3], k=3) < 1.0
