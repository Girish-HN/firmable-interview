"""Build the Golden Set: 150 Companies for a human to label, pre-filled by Claude Opus 5.5.

Sample (seeded): top 50 by pre-Fit priority, 50 from the middle band (ranks 2,001-20,000), and 50 random
Companies with Need > 0. 20 rows are left blind (no pre-fill) to measure whether pre-fills anchor the labeller.

Writes:
  data/golden/golden_labels.csv  - the file the human edits in Excel (h_* columns)
  data/golden/golden_key.csv     - stratum, blind flag and Opus pre-fills, for scripts/eval_golden.py
Usage: python scripts/golden_set.py
"""
import csv
import json
import random
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import duckdb

from classify_industry import INDUSTRIES, company_evidence, evidence_text
from llm import OPUS, json_call, spend_so_far

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "processed"
OUT = ROOT / "data" / "golden"
SEED = 42
PER_STRATUM = 50
BLIND = 20

SCHEMA = {
    "type": "object",
    "properties": {
        "industry": {"type": "string", "enum": INDUSTRIES},
        "is_landlord": {"type": "boolean"},
        "attribution_correct": {"type": "boolean"},
        "credible_lead": {"type": "boolean"},
        "rationale": {"type": "string"},
    },
    "required": ["industry", "is_landlord", "attribution_correct", "credible_lead", "rationale"],
    "additionalProperties": False,
}
SYSTEM = """You help build a hand-checked evaluation set for a cybersecurity vendor's lead-ranking tool. Each \
record is one organisation, identified by its domain, with evidence scraped from internet-facing servers and \
the security findings the tool attached to it.

Judge:
- industry: the organisation's own line of business ("unknown" if the evidence doesn't support a guess).
- is_landlord: true if it mainly provides internet infrastructure to many unrelated parties (hosting, VPS/cloud, \
ISP/telecom, CDN, domain parking, website builders, shared university or research networks).
- attribution_correct: true if the servers and findings plausibly belong to this domain's owner, rather than to \
customers or tenants of a provider, or to an unrelated party.
- credible_lead: true only if this is a real organisation that could plausibly buy security software, it is not \
a landlord, the attribution is correct, and at least one finding is a genuine security concern for it.
- rationale: one sentence, at most 30 words, naming the deciding evidence."""


def sample(con):
    con.sql(f"""
        create table ranked as
        select company, need * urgency as priority, risky_ips, reasons, worst_ip,
               row_number() over (order by need * urgency desc, risky_ips desc) as rk
        from '{(DATA / 'scored_companies.parquet').as_posix()}' where need > 0""")
    rng = random.Random(SEED)
    top = [r[0] for r in con.sql(f"select company from ranked where rk <= {PER_STRATUM} order by rk").fetchall()]
    middle_pool = [r[0] for r in con.sql("select company from ranked where rk between 2001 and 20000 order by rk").fetchall()]
    middle = rng.sample(middle_pool, PER_STRATUM)
    taken = set(top) | set(middle)
    random_pool = [r[0] for r in con.sql("select company from ranked order by rk").fetchall() if r[0] not in taken]
    rand = rng.sample(random_pool, PER_STRATUM)
    return [(c, "top") for c in top] + [(c, "middle") for c in middle] + [(c, "random") for c in rand]


def main():
    con = duckdb.connect()
    picks = sample(con)
    strata = dict(picks)
    con.execute("create table picks (company varchar)")
    con.executemany("insert into picks values (?)", [(c,) for c, _ in picks])
    rows = company_evidence(con, "select r.company, r.priority from ranked r join picks using (company)")
    evidence = {row[0]: evidence_text(row) for row in rows}
    findings = {c: (reasons, worst_ip) for c, reasons, worst_ip in
                con.sql("select company, reasons, worst_ip from ranked join picks using (company)").fetchall()}

    def label(company):
        reasons, worst_ip = findings[company]
        user = json.dumps({"evidence": json.loads(evidence[company]), "findings": reasons,
                           "riskiest_ip": worst_ip}, ensure_ascii=False)
        parsed, _ = json_call(OPUS, SYSTEM, user, SCHEMA, purpose="golden_prefill", effort="low", max_tokens=4000)
        return company, parsed or {}

    with ThreadPoolExecutor(6) as pool:
        prefills = dict(pool.map(label, [c for c, _ in picks]))

    rng = random.Random(SEED + 1)
    order = [c for c, _ in picks]
    rng.shuffle(order)  # so strata aren't visible from row position
    blind = set(rng.sample(order, BLIND))

    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "golden_labels.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["row", "company", "url", "page_titles", "certificate_organisations", "findings",
                    "h_industry", "h_is_landlord", "h_attribution_correct", "h_credible_lead", "notes"])
        for i, c in enumerate(order, 1):
            ev = json.loads(evidence[c])
            p = {} if c in blind else prefills[c]
            yn = lambda v: "" if v is None else ("yes" if v else "no")
            w.writerow([i, c, f"https://{c}", " | ".join(ev["page_titles"]), " | ".join(ev["certificate_organisations"]),
                        " ; ".join(findings[c][0]), p.get("industry", ""), yn(p.get("is_landlord")),
                        yn(p.get("attribution_correct")), yn(p.get("credible_lead")), ""])
    with open(OUT / "golden_key.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["company", "stratum", "blind", "opus_industry", "opus_is_landlord", "opus_attribution_correct",
                    "opus_credible_lead", "opus_rationale"])
        for c in order:
            p = prefills[c]
            w.writerow([c, strata[c], c in blind, p.get("industry"), p.get("is_landlord"),
                        p.get("attribution_correct"), p.get("credible_lead"), p.get("rationale")])

    print(f"wrote {len(order)} rows ({BLIND} blind) to {OUT}; total logged LLM spend ${spend_so_far():.4f}")


if __name__ == "__main__":
    main()
