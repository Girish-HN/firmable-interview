"""Industry classification v5: Haiku 5.5 for every Company, Sonnet 5.5 re-checks the ones sellers are most likely to see.

Rule (fixed before evaluation): Haiku 5.5 with prompt v1 classifies the top 5,000 Companies (industry_v1.parquet);
Sonnet 5.5 with the same prompt and evidence re-classifies the top SONNET_TOP by pre-Fit priority, and its answer
replaces Haiku's. Sonnet answers are cached per (company, evidence hash) in sonnet_cache.jsonl; the Golden Set run
from compare_models.py seeds it, since it used identical evidence.

Usage: python scripts/cascade.py
Writes data/processed/industry.parquet (production, used by score.py) and a copy as industry_v5.parquet.
"""
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import duckdb

from classify_industry import SCHEMA, company_evidence, evidence_text
from compare_models import SYSTEM_V1
from llm import SONNET, json_call, spend_so_far

DATA = Path(__file__).resolve().parent.parent / "data" / "processed"
CACHE_PATH = DATA / "sonnet_cache.jsonl"
SONNET_TOP = 300


def evidence_hash(text):
    return hashlib.sha1(text.encode()).hexdigest()[:16]


def load_cache(con, texts):
    cache = {}
    if CACHE_PATH.exists():
        with open(CACHE_PATH, encoding="utf-8") as f:
            for r in map(json.loads, f):
                cache[(r["company"], r["input_hash"])] = r
    elif (DATA / "model_compare.parquet").exists():
        # seed from the Golden Set comparison: same prompt, evidence verified identical to Haiku's v1 run
        seeds = con.sql(f"select * from '{(DATA / 'model_compare.parquet').as_posix()}'").fetchall()
        with open(CACHE_PATH, "w", encoding="utf-8") as out:
            for company, _, industry, is_landlord, confidence, evidence, cost in seeds:
                if company not in texts:
                    continue
                r = {"company": company, "input_hash": evidence_hash(texts[company]), "cost_usd": cost,
                     "industry": industry, "is_landlord": is_landlord, "confidence": confidence, "evidence": evidence}
                out.write(json.dumps(r) + "\n")
                cache[(company, r["input_hash"])] = r
    return cache


def main():
    con = duckdb.connect()
    rows = company_evidence(con, f"""
        select company, need * urgency as priority from '{(DATA / 'scored_companies.parquet').as_posix()}'
        where need * urgency > 0 order by priority desc, risky_ips desc, company limit {SONNET_TOP}""", v1_titles=True)
    texts = {r[0]: evidence_text(r) for r in rows}
    cache = load_cache(con, texts)
    todo = [c for c, t in texts.items() if (c, evidence_hash(t)) not in cache]
    print(f"top {len(texts)} Companies; {len(texts) - len(todo)} cached; calling Sonnet 5.5 for {len(todo)}")

    def classify(company):
        parsed, cost = json_call(SONNET, SYSTEM_V1, texts[company], SCHEMA, purpose="industry_sonnet", max_tokens=256)
        parsed = parsed or {"industry": "unknown", "is_landlord": False, "confidence": "low", "evidence": "no answer"}
        return {"company": company, "input_hash": evidence_hash(texts[company]), "cost_usd": cost, **parsed}

    with ThreadPoolExecutor(8) as pool, open(CACHE_PATH, "a", encoding="utf-8") as out:
        for r in pool.map(classify, todo):
            out.write(json.dumps(r) + "\n")
            cache[(r["company"], r["input_hash"])] = r

    sonnet = [cache[(c, evidence_hash(t))] for c, t in texts.items()]
    con.execute("create table s (company varchar, industry varchar, is_landlord boolean, confidence varchar, evidence varchar)")
    con.executemany("insert into s values (?, ?, ?, ?, ?)",
                    [(r["company"], r["industry"], r["is_landlord"], r["confidence"], r["evidence"]) for r in sonnet])
    con.sql(f"""
        create table v5 as
        select h.company, coalesce(s.industry, h.industry) as industry, coalesce(s.is_landlord, h.is_landlord) as is_landlord,
               coalesce(s.confidence, h.confidence) as confidence, coalesce(s.evidence, h.evidence) as evidence,
               case when s.company is null then 'claude-haiku-5-5' else 'claude-sonnet-5-5' end as model
        from '{(DATA / 'industry_v1.parquet').as_posix()}' h left join s using (company)""")
    for name in ("industry.parquet", "industry_v5.parquet"):
        con.sql(f"copy v5 to '{(DATA / name).as_posix()}' (format parquet)")

    changed = con.sql(f"""select count(*) filter (where v5.is_landlord <> h.is_landlord), count(*) filter (where v5.industry <> h.industry)
                          from v5 join '{(DATA / 'industry_v1.parquet').as_posix()}' h using (company) where v5.model = '{SONNET}'""").fetchone()
    print(f"Sonnet changed Haiku's landlord flag for {changed[0]} and industry for {changed[1]} of the top {len(texts)}; "
          f"total logged LLM spend ${spend_so_far():.4f}")


if __name__ == "__main__":
    main()
