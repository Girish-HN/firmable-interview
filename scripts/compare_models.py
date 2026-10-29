"""Does a bigger model fix Landlord detection? Re-run prompt v1 on the Golden Set Companies with Claude Sonnet 5.5.

Same prompt (v1) and the same evidence Haiku saw, so the model is the only difference. The evidence is checked
against the v1 cache keys before any call is made. Results go to data/processed/model_compare.parquet, which
eval_golden.py reports next to Haiku.

Usage: python scripts/compare_models.py
"""
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import duckdb

from classify_industry import SCHEMA, company_evidence, evidence_text
from llm import SONNET, json_call, spend_so_far

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "processed"
GOLDEN = ROOT / "data" / "golden"

# Prompt v1 verbatim, as used for the production Haiku run.
SYSTEM_V1 = """You classify organisations for a cybersecurity vendor's sales team, using only evidence scraped from \
their internet-facing servers (domain, web page titles, TLS certificate organisation names, server software).

Return:
- industry: the organisation's own line of business. Use "unknown" when the evidence doesn't support a guess; \
don't infer an industry from the domain's country or from generic page titles like "403 Forbidden".
- is_landlord: true if the organisation mainly provides internet infrastructure to many unrelated parties, so \
the servers seen are likely its customers' rather than its own. This covers web hosting, VPS/cloud providers, \
ISPs and telecoms, CDNs, domain parking, website builders, and shared university or research networks that \
host many independent departments or users. False for a business that merely runs its own website or servers.
- confidence: how strongly the evidence supports your answer.
- evidence: at most 20 words naming the specific clue you relied on."""


def main():
    con = duckdb.connect()
    rows = company_evidence(con, f"""
        select company, 1 as priority
        from read_csv_auto('{(GOLDEN / 'golden_key.csv').as_posix()}')
        where company in (select company from '{(DATA / 'industry_v1.parquet').as_posix()}')""", v1_titles=True)

    with open(DATA / "industry_cache.jsonl", encoding="utf-8") as f:
        v1_keys = {(r["company"], r["input_hash"]) for r in map(json.loads, f) if "prompt" not in r}
    texts = {r[0]: evidence_text(r) for r in rows}
    same = sum((c, hashlib.sha1(t.encode()).hexdigest()[:16]) in v1_keys for c, t in texts.items())
    print(f"{len(texts)} Golden Set Companies; evidence identical to Haiku's v1 run for {same}")

    def classify(company):
        parsed, cost = json_call(SONNET, SYSTEM_V1, texts[company], SCHEMA, purpose="model_compare", max_tokens=256)
        parsed = parsed or {"industry": "unknown", "is_landlord": False, "confidence": "low", "evidence": "no answer"}
        return {"company": company, "model": SONNET, "cost_usd": cost, **parsed}

    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(classify, texts))
    spent = sum(r["cost_usd"] for r in results)
    con.execute("create table m (company varchar, model varchar, industry varchar, is_landlord boolean, "
                "confidence varchar, evidence varchar, cost_usd double)")
    con.executemany("insert into m values (?, ?, ?, ?, ?, ?, ?)",
                    [(r["company"], r["model"], r["industry"], r["is_landlord"], r["confidence"], r["evidence"],
                      r["cost_usd"]) for r in results])
    con.sql(f"copy m to '{(DATA / 'model_compare.parquet').as_posix()}' (format parquet)")
    print(f"Sonnet 5.5: ${spent:.4f} for {len(results)} calls (${1000 * spent / len(results):.2f} per 1k Companies); "
          f"total logged LLM spend ${spend_so_far():.4f}")


if __name__ == "__main__":
    main()
