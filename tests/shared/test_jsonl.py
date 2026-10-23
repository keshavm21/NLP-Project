from vulntriage.jsonl import read_jsonl, write_jsonl
from vulntriage.schemas import Advisory


def test_jsonl_roundtrip(tmp_path, advisory: Advisory):
    path = tmp_path / "x.jsonl"
    assert write_jsonl(path, [advisory, advisory]) == 2
    items = read_jsonl(path, Advisory)
    assert items == [advisory, advisory]
