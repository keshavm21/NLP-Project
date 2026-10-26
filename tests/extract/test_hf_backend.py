from __future__ import annotations

import importlib.util
import json
from datetime import datetime

import pytest

from vulntriage.config import load_yaml
from vulntriage.extract.hf_backend import HFGenerator
from vulntriage.extract.llm import LLMExtractor
from vulntriage.schemas import Advisory


class FakeIds(list):
    """Stands in for a tensor: indexable, and .to(device) is a no-op."""

    def to(self, device):
        return self


class FakeTokenizer:
    pad_token_id = None
    eos_token_id = 0

    def __init__(self):
        self.vocab: dict[int, str] = {}
        self.calls = []

    def apply_chat_template(self, messages, add_generation_prompt, return_tensors, return_dict):
        self.calls.append((messages, add_generation_prompt, return_dict))
        prompt_ids = list(range(100, 100 + len(messages)))
        return {
            "input_ids": FakeIds([prompt_ids]),
            "attention_mask": FakeIds([[1] * len(messages)]),
        }

    def decode(self, ids, skip_special_tokens):
        return "".join(self.vocab[i] for i in ids)


class FakeModel:
    device = "cpu"

    def __init__(self, tokenizer, reply: str):
        self.tokenizer, self.reply, self.kwargs = tokenizer, reply, None

    def generate(self, input_ids, attention_mask, **kwargs):
        self.kwargs = kwargs
        new_ids = list(range(len(self.reply)))
        self.tokenizer.vocab.update(dict(zip(new_ids, self.reply, strict=True)))
        return [list(input_ids[0]) + new_ids]  # prompt + continuation, like transformers


def test_returns_only_the_new_tokens_with_greedy_decoding():
    tok = FakeTokenizer()
    model = FakeModel(tok, '{"affected": []}')
    gen = HFGenerator(model, tok, max_new_tokens=64)
    out = gen([{"role": "user", "content": "hi"}])
    assert out == '{"affected": []}'
    assert model.kwargs["do_sample"] is False and model.kwargs["max_new_tokens"] == 64
    assert model.kwargs["pad_token_id"] == 0  # falls back to eos when there is no pad token
    assert tok.calls[0][1] is True  # generation prompt added


def test_plugs_into_llm_extractor():
    text = "A heap overflow in libfoo before 2.4.3 allows code execution."
    reply = json.dumps(
        {"affected": [{"vendor": None, "product": "libfoo", "versions": ["before 2.4.3"]}]}
    )
    tok = FakeTokenizer()
    extractor = LLMExtractor(HFGenerator(FakeModel(tok, reply), tok), name="local", n_examples=0)
    adv = Advisory(id="CVE-2025-0005", source="nvd", published=datetime(2025, 8, 1), text=text)
    result = extractor.extract(adv)
    assert [(a.product.text, a.vers_range) for a in result.affected] == [
        ("libfoo", "vers:generic/<2.4.3")
    ]
    assert len(tok.calls[0][0]) == 2  # system + advisory (zero-shot)


def test_config_loads():
    cfg = load_yaml("configs/extract/llm_local.yaml")
    assert cfg["generation"]["do_sample"] is False
    assert load_yaml(cfg["prompt"]["path"])["system"]


@pytest.mark.skipif(
    importlib.util.find_spec("transformers") is not None, reason="ml extra installed"
)
def test_from_pretrained_without_ml_extra_explains_how_to_install():
    with pytest.raises(ImportError, match="setup-ml"):
        HFGenerator.from_pretrained("any/model")
