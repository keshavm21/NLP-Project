"""Local Hugging Face backend for LLMExtractor: `generate(messages) -> str` over a causal LM.

Serves the LoRA small-LLM system (base model + adapter) and any open instruct model.
Decoding is greedy, so outputs are reproducible. transformers/peft are imported only in
from_pretrained (needs the `ml` extra); HFGenerator itself works with any model/tokenizer pair
that has the transformers interface, which is how it is unit-tested without downloads.

    gen = HFGenerator.from_pretrained("Qwen/Qwen2.5-1.5B-Instruct", adapter_dir="models/...")
    extractor = LLMExtractor(gen, name="lora-qwen1.5b")
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulntriage.extract.llm import Message


class HFGenerator:
    """Callable chat generator around a loaded causal LM and its tokenizer."""

    def __init__(self, model: Any, tokenizer: Any, max_new_tokens: int = 512) -> None:
        self.model = model
        self.tokenizer = tokenizer
        self.max_new_tokens = max_new_tokens

    def __call__(self, messages: list[Message]) -> str:
        inputs = self.tokenizer.apply_chat_template(
            messages, add_generation_prompt=True, return_tensors="pt", return_dict=True
        )
        device = getattr(self.model, "device", None)
        if device is not None:
            inputs = {k: v.to(device) for k, v in inputs.items()}
        output = self.model.generate(
            **inputs,
            max_new_tokens=self.max_new_tokens,
            do_sample=False,
            pad_token_id=self.tokenizer.pad_token_id or self.tokenizer.eos_token_id,
        )
        prompt_len = len(inputs["input_ids"][0])
        return self.tokenizer.decode(output[0][prompt_len:], skip_special_tokens=True)

    @classmethod
    def from_pretrained(
        cls,
        model_name_or_path: str | Path,
        adapter_dir: str | Path | None = None,
        max_new_tokens: int = 512,
        dtype: str = "auto",
        device_map: str | None = "auto",
    ) -> HFGenerator:
        """Load a base model (and optionally a LoRA adapter on top of it)."""
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as e:
            raise ImportError("HFGenerator needs the ml extra: run `make setup-ml`") from e

        tokenizer = AutoTokenizer.from_pretrained(model_name_or_path)
        model = AutoModelForCausalLM.from_pretrained(
            model_name_or_path, torch_dtype=dtype, device_map=device_map
        )
        if adapter_dir is not None:
            from peft import PeftModel

            model = PeftModel.from_pretrained(model, adapter_dir)
        return cls(model.eval(), tokenizer, max_new_tokens)
