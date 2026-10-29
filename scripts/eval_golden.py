"""Score the LLM steps and the ranking against the human-labelled Golden Set, and report what they cost.

Reads data/golden/golden_labels.csv (human h_* columns), data/golden/golden_key.csv (strata, blind flag,
Opus pre-fills), data/processed/industry.parquet (Haiku), scored_companies.parquet and llm_calls.jsonl.
Writes docs/evaluation.md.

Usage: python scripts/eval_golden.py
"""
import json
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "processed"
GOLDEN = ROOT / "data" / "golden"
OUT = ROOT / "docs" / "evaluation.md"
# Blind rows whose labels were discussed with Claude while labelling; they no longer measure anchoring.
NOT_BLIND = ["regions4growth.am"]


def yn(col):
    return f"case lower(trim({col})) when 'yes' then true when 'no' then false end"


def prf(con, pred, truth, where="true"):
    """Precision, recall and n for a boolean prediction against human truth."""
    tp, fp, fn, n = con.sql(f"""
        select count(*) filter (where {pred} and {truth}), count(*) filter (where {pred} and not {truth}),
               count(*) filter (where not {pred} and {truth}), count(*)
        from g where {where} and {pred} is not null and {truth} is not null""").fetchone()
    p = tp / (tp + fp) if tp + fp else float("nan")
    r = tp / (tp + fn) if tp + fn else float("nan")
    return p, r, n


def main():
    con = duckdb.connect()
    con.sql(f"""
        create table g as
        select k.company, k.stratum, k.blind,
               nullif(lower(trim(l.h_industry)), '') as h_industry,
               {yn('l.h_is_landlord')} as h_landlord, {yn('l.h_attribution_correct')} as h_attr,
               {yn('l.h_credible_lead')} as h_credible,
               k.opus_industry, k.opus_is_landlord as opus_landlord, k.opus_credible_lead as opus_credible,
               i.industry as v5_industry, i.is_landlord as v5_landlord,
               i3.industry as haiku_v3_industry, i3.is_landlord as haiku_v3_landlord,
               i1.industry as haiku_v1_industry, i1.is_landlord as haiku_v1_landlord,
               s.fit, s1.fit as fit_v1, s3.fit as fit_v3, s.priority, s.priority_before_fit
        from read_csv_auto('{(GOLDEN / 'golden_key.csv').as_posix()}') k
        join read_csv_auto('{(GOLDEN / 'golden_labels.csv').as_posix()}', all_varchar = true) l using (company)
        left join '{(DATA / 'industry.parquet').as_posix()}' i using (company)
        left join '{(DATA / 'scored_companies.parquet').as_posix()}' s using (company)
        -- earlier versions, kept to show the effect of each change (production = v5)
        left join '{(DATA / 'industry_v1.parquet').as_posix()}' i1 using (company)
        left join '{(DATA / 'scored_companies_v1.parquet').as_posix()}' s1 using (company)
        left join '{(DATA / 'industry_v3.parquet').as_posix()}' i3 using (company)
        left join '{(DATA / 'scored_companies_v3.parquet').as_posix()}' s3 using (company)""")
    labelled = con.sql("select count(*) from g where h_landlord is not null").fetchone()[0]

    lines = ["# Evaluation", "",
             "Reproduce: `python scripts/golden_set.py` (sample + Opus pre-fills), label "
             "`data/golden/golden_labels.csv` by hand, then `python scripts/eval_golden.py`.", "",
             f"Golden Set: 150 Companies (50 top-ranked before Fit, 50 mid-ranked, 50 random with Need > 0); "
             f"{labelled} labelled, 20 of them blind (no pre-fill shown). "
             "Labels were researched per Company with Google Gemini (a different model family from Claude, with web "
             "access to the live sites) and entered by hand: independent of Claude, but AI-assisted rather than purely human.", ""]

    # 1. Is the Landlord filter right? Haiku drives Fit, so Haiku is the model under test.
    lines += ["## 1. Landlord detection (drives Fit = 0)", "",
              "| Model | Precision | Recall | n |", "|---|---|---|---|"]
    for name, col in [("Claude Haiku 5.5, prompt v1", "haiku_v1_landlord"),
                      ("Claude Haiku 5.5, prompt v3 (rejected)", "haiku_v3_landlord"),
                      ("v5: Haiku v1 + Sonnet 5.5 on the top 300 (production)", "v5_landlord"),
                      ("Claude Opus 5.5 (pre-fill)", "opus_landlord")]:
        p, r, n = prf(con, col, "h_landlord")
        lines.append(f"| {name} | {p:.0%} | {r:.0%} | {n} |")
    lines += ["", "v5 (production) is a rule fixed before it was evaluated: Haiku 5.5 with prompt v1 classifies the "
              "top 5,000 Companies, and Sonnet 5.5 with the same prompt and evidence re-checks the top 300 by pre-Fit "
              "priority (the ones most likely to reach a seller), replacing Haiku's answer. Every top-stratum Golden "
              "Set Company is in that top 300; middle and random rows keep Haiku's answer, as in production.", ""]
    lines += ["Prompt v3 adds rules for single universities and SaaS companies (not Landlords) and city education "
              "networks (Landlords), and drops generic page titles (\"301 Moved Permanently\") from the evidence so the "
              "informative ones fit. It was written after reading the v1 errors on this same set, so its numbers are "
              "optimistic; a fresh sample would give an unbiased estimate.", ""]
    # Bigger model, same prompt (v1) and same evidence: only the model differs (scripts/compare_models.py).
    compare = DATA / "model_compare.parquet"
    if compare.exists():
        con.sql(f"""create table mc as select g.*, m.is_landlord as sonnet_landlord, m.industry as sonnet_industry
                    from g join '{compare.as_posix()}' m using (company)""")
        lines += ["Same prompt (v1) and identical evidence, on the Golden Set Companies both models classified:", "",
                  "| Model | Precision | Recall | Industry accuracy | USD per 1,000 Companies | n |", "|---|---|---|---|---|---|"]
        cost = {"haiku": con.sql(f"""select 1000 * avg(cost_usd) from read_json_auto('{(DATA / 'llm_calls.jsonl').as_posix()}')
                                    where purpose = 'industry'""").fetchone()[0],
                "sonnet": con.sql(f"select 1000 * avg(cost_usd) from '{compare.as_posix()}'").fetchone()[0]}
        for name, key, col, ind in [("Claude Haiku 5.5", "haiku", "haiku_v1_landlord", "haiku_v1_industry"),
                                    ("Claude Sonnet 5.5", "sonnet", "sonnet_landlord", "sonnet_industry")]:
            tp, fp, fn, acc, n = con.sql(f"""select count(*) filter (where {col} and h_landlord),
                    count(*) filter (where {col} and not h_landlord), count(*) filter (where not {col} and h_landlord),
                    avg(({ind} = h_industry)::int), count(*) from mc where h_landlord is not null""").fetchone()
            lines.append(f"| {name} | {tp / (tp + fp):.0%} | {tp / (tp + fn):.0%} | {acc:.0%} | ${cost[key]:.2f} | {n} |")
        lines += ["", "Both models miss the same thin-evidence ISPs and hosts (e.g. teletek.net.tr, syncwave.net, "
                  "5july.net): the clue isn't in the scan data, so a bigger model can't see it either.", ""]
    for name, col in [("Haiku v1", "haiku_v1_industry"), ("Haiku v3", "haiku_v3_industry"), ("v5", "v5_industry")]:
        acc = con.sql(f"""select avg(({col} = h_industry)::int), count(*) from g
                          where {col} is not null and h_industry is not null""").fetchone()
        lines.append(f"Industry exact-match accuracy ({name} vs. labels): **{acc[0]:.0%}** over {acc[1]} Companies.  ")
    lines += ["(Haiku only classified the top 5,000, so random-stratum rows are partly uncovered.)", ""]

    # 2. Did pre-fills anchor the labeller? Compare human-Opus agreement on pre-filled vs blind rows.
    agree = con.sql(f"""select blind, avg((opus_landlord = h_landlord)::int), avg((opus_credible = h_credible)::int), count(*)
                       from g where h_landlord is not null and company not in {tuple(NOT_BLIND) + ('',)}
                       group by blind order by blind""").fetchall()
    lines += ["## 2. Anchoring check", "", "| Rows | Labels agree with Opus: landlord | credible lead | n |", "|---|---|---|---|"]
    for blind, a_l, a_c, n in agree:
        lines.append(f"| {'blind (no pre-fill)' if blind else 'pre-filled'} | {a_l:.0%} | {a_c:.0%} | {n} |")
    lines += ["", "Agreement much higher on pre-filled rows than blind ones would mean the pre-fills anchored the "
              "labels; the blind rows are then the more trustworthy measure. "
              f"Excluded: {len(NOT_BLIND)} blind row(s) discussed with Claude during labelling.", ""]

    # 3. Does the ranking put credible leads on top, and did Fit help?
    lines += ["## 3. Ranking quality", "", "| Stratum | Credible leads (labels) | Landlords (labels) | n |", "|---|---|---|---|"]
    for stratum, cred, land, n in con.sql("""
            select stratum, avg(h_credible::int), avg(h_landlord::int), count(*) from g
            where h_credible is not null group by 1 order by case stratum when 'top' then 1 when 'middle' then 2 else 3 end""").fetchall():
        lines.append(f"| {stratum} | {cred:.0%} | {land:.0%} | {n} |")
    lines += ["", "Within the pre-Fit top 50:", "",
              "| Version | Kept by Fit: credible leads | n | Removed by Fit (Fit = 0): correctly not leads | n |",
              "|---|---|---|---|---|"]
    for name, fit in [("Haiku v1", "fit_v1"), ("Haiku v3", "fit_v3"), ("v5", "fit")]:
        kept = con.sql(f"""select avg(h_credible::int), count(*) from g
                           where stratum = 'top' and {fit} > 0 and h_credible is not null""").fetchone()
        dropped = con.sql(f"""select avg((not h_credible)::int), count(*) from g
                              where stratum = 'top' and {fit} = 0 and h_credible is not null""").fetchone()
        lines.append(f"| {name} | {kept[0] or 0:.0%} | {kept[1]} | {dropped[0] or 0:.0%} | {dropped[1]} |")
    lines.append("")

    # 4. Consistency: Companies classified twice on near-identical evidence before the cache key was fixed.
    repeats = con.sql(f"""
        with paid as (select company, industry, is_landlord
                      from read_json_auto('{(DATA / 'industry_cache.jsonl').as_posix()}', sample_size = -1)
                      where cost_usd > 0 and prompt is null),  -- v1 rows predate the prompt field
             c as (select company, count(*) k, count(distinct is_landlord) l, count(distinct industry) i from paid group by 1)
        select count(*) filter (where k > 1), count(*) filter (where k > 1 and l > 1), count(*) filter (where k > 1 and i > 1)
        from c""").fetchone()
    lines += ["## 4. Run-to-run consistency", "",
              f"{repeats[0]:,} Companies were classified twice by Haiku on near-identical evidence (an early cache-key bug: "
              f"list order and tie-breaks varied between runs). The landlord flag flipped for **{repeats[1]}** "
              f"({repeats[1] / max(repeats[0], 1):.1%}) and the industry for {repeats[2]} ({repeats[2] / max(repeats[0], 1):.1%}). "
              "Evidence is now canonicalised, so a re-run makes zero calls and reproduces the same labels.", ""]

    # 5. Cost
    lines += ["## 5. Cost", "", "| Step | Model | Calls | USD |", "|---|---|---|---|"]
    for purpose, model, calls, usd in con.sql(f"""
            select purpose, model, count(*), sum(cost_usd) from read_json_auto('{(DATA / 'llm_calls.jsonl').as_posix()}')
            group by 1, 2 order by 4 desc""").fetchall():
        lines.append(f"| {purpose} | `{model}` | {calls:,} | ${usd:.3f} |")
    total = con.sql(f"select sum(cost_usd) from read_json_auto('{(DATA / 'llm_calls.jsonl').as_posix()}')").fetchone()[0]
    # production (v5) = Haiku prompt v1 on every Company + Sonnet 5.5 on the top 300
    haiku_1k = con.sql(f"""select 1000 * avg(cost_usd)
                           from read_json_auto('{(DATA / 'industry_cache.jsonl').as_posix()}', sample_size = -1)
                           where cost_usd > 0 and prompt is null""").fetchone()[0]
    sonnet_call = con.sql(f"""select avg(cost_usd) from read_json_auto('{(DATA / 'llm_calls.jsonl').as_posix()}')
                              where model = 'claude-sonnet-5-5'""").fetchone()[0]
    per_file = 5 * haiku_1k + 300 * sonnet_call
    lines += ["", f"Total spent: **${total:.2f}**, including prompt v1, the rejected v3 (two small trials and a full re-run) "
              f"and the Sonnet comparison. Production (v5) per Scan File: Haiku 5.5 on 5,000 Companies at "
              f"${haiku_1k:.3f} per 1,000, plus Sonnet 5.5 on the top 300 at ${1000 * sonnet_call:.2f} per 1,000: "
              f"**about ${per_file:.2f} per file**.", ""]

    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
