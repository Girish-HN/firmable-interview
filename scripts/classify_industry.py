"""Classify each high-Need Company's industry, and whether it is a Landlord, from its own Banners' text.

Evidence per Company: domain, page titles, certificate organisation names, server software, web components,
country and footprint size. Results are cached per (company, evidence hash) in industry_cache.jsonl, so
re-runs only pay for new or changed Companies.

Usage: python scripts/classify_industry.py [limit]   (default 5000, ordered by Priority Score)
Writes data/processed/industry.parquet
"""
import hashlib
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import duckdb

from llm import HAIKU, json_call, spend_so_far

DATA = Path(__file__).resolve().parent.parent / "data" / "processed"
CACHE_PATH = DATA / "industry_cache.jsonl"
WORKERS = 8

INDUSTRIES = [
    "healthcare", "finance", "legal", "education", "government", "retail_ecommerce", "manufacturing",
    "technology_saas", "media", "hospitality", "nonprofit", "hosting_isp_cloud", "other", "unknown",
]
SCHEMA = {
    "type": "object",
    "properties": {
        "industry": {"type": "string", "enum": INDUSTRIES},
        "is_landlord": {"type": "boolean"},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "evidence": {"type": "string"},
    },
    "required": ["industry", "is_landlord", "confidence", "evidence"],
    "additionalProperties": False,
}
SYSTEM = """You classify organisations for a cybersecurity vendor's sales team, using only evidence scraped from \
their internet-facing servers (domain, web page titles, TLS certificate organisation names, server software).

Return:
- industry: the organisation's own line of business. Use "unknown" when the evidence doesn't support a guess; \
don't infer an industry from the domain's country or from generic page titles like "403 Forbidden".
- is_landlord: true if the organisation mainly provides internet infrastructure to many unrelated parties, so \
the servers seen are likely its customers' rather than its own. This covers web hosting, VPS/cloud providers, \
ISPs and telecoms, CDNs, domain parking and website builders. Clues: titles naming several unrelated businesses, \
hosting control panels (cPanel, Plesk, DirectAdmin, FASTPANEL, Webmin, Vesta), consumer routers or NAS boxes on \
one domain, or machine-style domains (ip-1-2-3, vps, srv).
  False for a business that merely runs its own website or servers. Also false for:
  - a university, college, school or research institute whose titles show its own central services (library, \
admissions, student or staff portals, e-learning, its institutes' projects): it controls those servers. Only a \
network hosting many independently run tenants is a landlord, e.g. a district or city education network whose \
titles name several different schools or centres, or a campus whose titles are unrelated organisations' or \
student or club sites.
  - a software company running its own product for many customers (SaaS, a mail or marketing platform): many \
customers or many servers is not the test; many unrelated server owners is.
- confidence: how strongly the evidence supports your answer.
- evidence: at most 20 words naming the specific clue you relied on."""
# Part of the cache key: changing SYSTEM must re-classify. v1 (no "prompt" field in the cache) is kept for comparison.
PROMPT_VERSION = "v3"
GENERIC_TITLE = (r"^\s*(\d{3}\b|moved|found|forbidden|not found|bad request|unauthorized|error|redirect|"
                 r"welcome to nginx|apache.*(test|default) page|.*default (web site )?page|one moment|just a moment|"
                 r"index of|it works|iis windows server|service unavailable|page redirecting|site not found)")


def load_companies(limit):
    """Top Companies by pre-Fit priority (Need x Urgency), so re-runs select the same set after Fit is applied."""
    con = duckdb.connect()
    return company_evidence(con, f"""
        select company, need * urgency as priority from '{(DATA / 'scored_companies.parquet').as_posix()}'
        where need * urgency > 0 order by priority desc, risky_ips desc, company limit {limit}"""), con


def company_evidence(con, companies_sql, v1_titles=False):
    """Evidence rows for the Companies selected by `companies_sql` (columns: company, priority).
    v1_titles reproduces prompt v1's evidence (first 5 titles, generic ones included) for model comparisons."""
    title_filter = "true" if v1_titles else f"not regexp_matches(a.title, '{GENERIC_TITLE}', 'i')"
    n_titles = 5 if v1_titles else 8
    return con.sql(f"""
        with top as ({companies_sql})
        select a.company,
          -- sort before slicing: the slice must pick the same items every run (they key the cache)
          -- generic titles ("301 Moved Permanently", "Welcome to nginx!") sort first and crowded out the
          -- informative ones (tyc.edu.tw's school names), so they're dropped before the slice
          list_sort(list(distinct a.title) filter (where a.title is not null and {title_filter}))[:{n_titles}] as titles,
          list_sort(list(distinct a.cert_org) filter (where a.cert_org is not null))[:3] as cert_orgs,
          list_sort(list(distinct a.server_header) filter (where a.server_header is not null))[:3] as servers,
          list_sort(list(distinct a.x_powered_by) filter (where a.x_powered_by is not null))[:2] as powered_by,
          list_sort(list(distinct c) filter (where c is not null))[:10] as components,
          list_sort(list(distinct a.country) filter (where a.country is not null))[:3] as countries,
          count(distinct a.ip) as ips, any_value(top.priority) as priority
        from '{(DATA / 'attributed.parquet').as_posix()}' a
        join top using (company)
        left join (select company, unnest(components) as c from '{(DATA / 'attributed.parquet').as_posix()}'
                   where company in (select company from top)) comp using (company)
        group by a.company order by priority desc""").fetchall()


def evidence_text(row):
    """Canonical evidence JSON. Lists are sorted because SQL returns them in arbitrary order, and the text's
    hash is the cache key: unsorted lists re-classified identical evidence (and 3 of 45 such repeats flipped)."""
    company, titles, cert_orgs, servers, powered_by, components, countries, ips, _ = row
    return json.dumps({
        "domain": company, "page_titles": sorted(titles or []), "certificate_organisations": sorted(cert_orgs or []),
        "server_software": sorted((servers or []) + (powered_by or [])),
        "web_components": sorted(c for c in components or [] if c),
        "server_countries": countries or [], "distinct_ips_seen": ips,
    }, ensure_ascii=False, sort_keys=True)


def load_cache():
    cache = {}
    if CACHE_PATH.exists():
        with open(CACHE_PATH, encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                cache[(r["company"], r["input_hash"], r.get("prompt", "v1"))] = r
    return cache


def classify(company, text, input_hash):
    parsed, cost = json_call(HAIKU, SYSTEM, text, SCHEMA, purpose="industry", max_tokens=256)
    parsed = parsed or {"industry": "unknown", "is_landlord": False, "confidence": "low", "evidence": "no answer"}
    return {"company": company, "input_hash": input_hash, "prompt": PROMPT_VERSION, "cost_usd": cost, **parsed}


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    rows, con = load_companies(limit)
    cache = load_cache()
    todo = []
    for row in rows:
        text = evidence_text(row)
        h = hashlib.sha1(text.encode()).hexdigest()[:16]
        if (row[0], h, PROMPT_VERSION) not in cache:
            todo.append((row[0], text, h))
    print(f"{len(rows):,} Companies; {len(rows) - len(todo):,} cached; calling Claude for {len(todo):,}")

    spent = 0.0
    with ThreadPoolExecutor(WORKERS) as pool, open(CACHE_PATH, "a", encoding="utf-8") as out:
        futures = [pool.submit(classify, *t) for t in todo]
        for i, fut in enumerate(as_completed(futures), 1):
            result = fut.result()
            spent += result["cost_usd"]
            out.write(json.dumps(result) + "\n")
            out.flush()
            cache[(result["company"], result["input_hash"], PROMPT_VERSION)] = result
            if i % 250 == 0:
                print(f"  {i:,}/{len(todo):,}  ${spent:.4f}", flush=True)

    keep = {(row[0], hashlib.sha1(evidence_text(row).encode()).hexdigest()[:16], PROMPT_VERSION) for row in rows}
    results = [r for k, r in cache.items() if k in keep]
    con.execute("create table industry (company varchar, industry varchar, is_landlord boolean, "
                "confidence varchar, evidence varchar)")
    con.executemany("insert into industry values (?, ?, ?, ?, ?)",
                    [(r["company"], r["industry"], r["is_landlord"], r["confidence"], r["evidence"]) for r in results])
    con.sql(f"copy industry to '{(DATA / 'industry.parquet').as_posix()}' (format parquet)")

    n = max(len(todo), 1)
    print(f"this run: ${spent:.4f} for {len(todo):,} calls (${1000 * spent / n:.3f} per 1k Companies); "
          f"total logged LLM spend ${spend_so_far():.4f}")
    print(con.sql("select industry, count(*) n, sum(is_landlord::int) landlords from industry group by 1 order by 2 desc"))


if __name__ == "__main__":
    main()
