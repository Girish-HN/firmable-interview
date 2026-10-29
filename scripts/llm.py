"""Shared Claude client: structured JSON calls, per-call cost accounting, and an append-only call log.

Every call is logged to data/processed/llm_calls.jsonl (model, purpose, tokens, dollars), which is the
source of truth for "what did the LLM steps cost".

Usage (smoke test): python scripts/llm.py
"""
import json
import threading
import time
from pathlib import Path

import anthropic
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
LOG_PATH = ROOT / "data" / "processed" / "llm_calls.jsonl"
load_dotenv(ROOT / ".env")

HAIKU = "claude-haiku-5-5"
SONNET = "claude-sonnet-5-5"
OPUS = "claude-opus-5-5"
# USD per million tokens: input, output, cache write (5m), cache read. Source: platform.claude.com pricing, 2026-10-29.
PRICES = {
    HAIKU: (0.10, 0.50, 0.125, 0.01),
    SONNET: (2.00, 10.00, 2.50, 0.20),
    OPUS: (4.00, 20.00, 5.00, 0.20),
}

client = anthropic.Anthropic(max_retries=5)
_log_lock = threading.Lock()


def cost_usd(model, usage):
    p_in, p_out, p_write, p_read = PRICES[model]
    return (usage.input_tokens * p_in + usage.output_tokens * p_out
            + (usage.cache_creation_input_tokens or 0) * p_write
            + (usage.cache_read_input_tokens or 0) * p_read) / 1e6


def _log(record):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _log_lock, open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def json_call(model, system, user, schema, purpose, effort="low", max_tokens=1024):
    """One request constrained to `schema`. Returns (parsed dict or None, cost in USD).

    None means the model refused or produced no usable JSON; callers record that as 'unknown'.
    """
    params = dict(
        model=model,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
        output_config={"effort": effort, "format": {"type": "json_schema", "schema": schema}},
        cache_control={"type": "ephemeral"},
    )
    t0 = time.time()
    if model == OPUS:
        # Opus 5.5 always thinks; server-side fallbacks re-run a policy decline on a fallback model.
        response = client.beta.messages.create(
            **params, betas=["server-side-fallback-2026-07-01"], fallbacks="default")
    elif model == SONNET:
        # Sonnet 5.5 rejects thinking "disabled"; "between_tools" turns it off (effort <= high). Same fallbacks as Opus.
        response = client.beta.messages.create(
            **params, thinking={"type": "between_tools"}, betas=["server-side-fallback-2026-07-01"], fallbacks="default")
    else:
        # Classification gains nothing from thinking; Haiku 5.5 allows disabling it at effort <= high.
        response = client.messages.create(**params, thinking={"type": "disabled"})

    usage = response.usage
    cost = cost_usd(model, usage)
    parsed = None
    if response.stop_reason not in ("refusal", "max_tokens"):
        text = next((b.text for b in response.content if b.type == "text"), None)
        try:
            parsed = json.loads(text) if text else None
        except json.JSONDecodeError:
            parsed = None
    _log({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "model": model, "purpose": purpose,
        "stop_reason": response.stop_reason, "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens, "cache_read": usage.cache_read_input_tokens or 0,
        "cost_usd": round(cost, 6), "seconds": round(time.time() - t0, 2), "ok": parsed is not None,
    })
    return parsed, cost


def spend_so_far():
    if not LOG_PATH.exists():
        return 0.0
    with open(LOG_PATH, encoding="utf-8") as f:
        return sum(json.loads(line)["cost_usd"] for line in f)


if __name__ == "__main__":
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}, "word": {"type": "string"}},
              "required": ["ok", "word"], "additionalProperties": False}
    result, cost = json_call(HAIKU, "Reply with JSON only.", "Say ok=true and one word describing the sky.",
                             schema, purpose="smoke_test", max_tokens=64)
    print("result:", result, f"| cost ${cost:.6f} | total logged spend ${spend_so_far():.6f}")
