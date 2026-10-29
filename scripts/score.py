"""Stage 7 (Score): Priority Score = Need x Urgency x Fit, with a readable reason for every point.

Weights for lift-validated Signals are ln(single-IP lift) measured from the data (see docs/signal-analysis.md),
so they're recomputed, not hand-tuned. Exposure and Urgency Signals can't be validated by lift and use the
fixed values below, justified in docs/signal-analysis.md section 5. Fit comes from the LLM industry
classification (scripts/classify_industry.py): Landlords 0, regulated industries 1.25, everything else 1.0.

Need is scored per IP and a Company takes its riskiest IP: one bad server is enough for a breach, and summing
Signals across a footprint ranks hosting providers first simply because they own more servers.

Usage: python scripts/score.py
Reads data/processed/{attributed,company_signals}.parquet, writes data/processed/scored_companies.parquet.
"""
import math
from pathlib import Path

import duckdb

from analyze_signals import SIGNALS

DATA = Path(__file__).resolve().parent.parent / "data" / "processed"

# Need: weight = ln(single-IP lift). CVE-derived Signals share one input, so only the strongest counts.
CVE_FAMILY = ["kev_cve", "high_epss", "critical_cvss"]
LIFT_WEIGHTED = ["eol_software", "outdated_runtime", "default_page", "stale_site_3y", "open_directory", "cert_expired"]
MATURITY = ["has_waf"]

# Need, exposure: access risk that KEV lift can't see. ln(e) = 1.0 is a deliberately moderate weight.
EXPOSURE_WEIGHT = 1.0
EXPOSURE = ["exposed_rdp", "exposed_database", "exposed_remote_shell", "ics_or_medical"]

# Urgency multiplies Need: Priority = Need x (1 + sum of urgency points).
URGENCY = {
    "compromised": 1.0,         # already breached
    "ransomware_cve": 0.5,      # a KEV CVE that CISA links to ransomware campaigns
    "takeover_candidate": 0.5,  # a hostname anyone could claim today
    "cert_expiring_30d": 0.25,  # visible outage within a month
}

# Fit: a modest boost for regulated industries, where a breach also brings regulatory exposure.
REGULATED = ["healthcare", "finance", "legal", "education", "government"]
REGULATED_FIT = 1.25

LABELS = {
    "kev_cve": "actively exploited CVE (CISA KEV)",
    "high_epss": "CVE likely to be exploited soon (EPSS >= 0.5)",
    "critical_cvss": "critical-severity CVE (CVSS >= 9)",
    "eol_software": "end-of-life software",
    "outdated_runtime": "outdated PHP / ASP.NET",
    "default_page": "default server page left exposed",
    "stale_site_3y": "website unchanged for 3+ years",
    "open_directory": "open directory listing",
    "cert_expired": "expired TLS certificate",
    "has_waf": "already behind a web application firewall",
    "exposed_rdp": "Remote Desktop open to the internet",
    "exposed_database": "database open to the internet",
    "exposed_remote_shell": "Telnet / VNC open to the internet",
    "ics_or_medical": "industrial or medical device exposed",
    "compromised": "signs of compromise",
    "ransomware_cve": "CVE used in ransomware campaigns",
    "takeover_candidate": "subdomain takeover possible",
    "cert_expiring_30d": "TLS certificate expires within 30 days",
}


def single_ip_lift_weights(con):
    """ln(P(KEV | signal) / P(KEV)) among single-IP Companies, the size-controlled lift."""
    base = con.sql("select avg(kev_cve::int) from cs where ips = 1").fetchone()[0]
    weights = {}
    for name in CVE_FAMILY + LIFT_WEIGHTED + MATURITY:
        rate = con.sql(f"select avg(kev_cve::int) from cs where ips = 1 and {name}").fetchone()[0]
        weights[name] = round(math.log(rate / base), 2)
    return weights


def main():
    con = duckdb.connect()
    con.sql(f"create view cs as select * from '{(DATA / 'company_signals.parquet').as_posix()}'")
    w = single_ip_lift_weights(con)
    for name, value in w.items():
        print(f"  {name:20} {value:+.2f}")

    def term(name, weight):
        return f"case when {name} then {weight} else 0 end"

    def reason(name, weight):
        return f"case when {name} then '{weight:+.2f} {LABELS[name]}' end"

    cve_points = "greatest(" + ", ".join(term(n, w[n]) for n in CVE_FAMILY) + ")"
    cve_reason = ("case " + " ".join(f"when {term(n, w[n])} = {cve_points} and {n} then '{w[n]:+.2f} {LABELS[n]}'"
                                     for n in CVE_FAMILY) + " end")
    need_terms = [cve_points] + [term(n, w[n]) for n in LIFT_WEIGHTED + MATURITY] + \
                 [term(n, EXPOSURE_WEIGHT) for n in EXPOSURE]
    urgency_terms = [term(n, v) for n, v in URGENCY.items()]
    reasons = [cve_reason] + [reason(n, w[n]) for n in LIFT_WEIGHTED + MATURITY] + \
              [reason(n, EXPOSURE_WEIGHT) for n in EXPOSURE] + \
              [f"case when {n} then 'x{1 + v:.2f} urgency: {LABELS[n]}' end" for n, v in URGENCY.items()]

    industry_path = DATA / "industry.parquet"
    industry_source = (f"'{industry_path.as_posix()}'" if industry_path.exists() else
                       "(select null::varchar company, null::varchar industry, null::boolean is_landlord, "
                       "null::varchar evidence where false)")

    need_signals = CVE_FAMILY + LIFT_WEIGHTED + MATURITY + EXPOSURE
    flags = ",\n".join(f"bool_or(coalesce({SIGNALS[n]}, false)) as {n}" for n in need_signals)
    con.sql(f"""
        create table ip_need as
        with ip_flags as (
          select company, ip, {flags}
          from '{(DATA / 'attributed.parquet').as_posix()}'
          where company is not null group by company, ip
        )
        select company, ip,
          greatest(0, {' + '.join(need_terms)}) as need,
          list_filter([{', '.join(reasons[:len(need_terms)])}], x -> x is not null) as reasons
        from ip_flags""")

    con.sql(f"""
        create table scored as
        with worst as (
          select company, max(need) as need, arg_max(ip, need) as worst_ip, arg_max(reasons, need) as reasons,
                 count(*) filter (where need > 0) as risky_ips
          from ip_need group by company
        ),
        s as (
          select cs.company, cs.country, cs.services, cs.ips, worst.risky_ips, worst.worst_ip,
            ind.industry, ind.is_landlord, ind.evidence as industry_evidence,
            worst.need,
            1 + {' + '.join(urgency_terms)} as urgency,
            case when ind.is_landlord then 0.0
                 when ind.industry in {tuple(REGULATED)} then {REGULATED_FIT}
                 else 1.0 end as fit,
            worst.reasons || list_filter([{', '.join(reasons[len(need_terms):])}], x -> x is not null)
              || [case when ind.is_landlord then 'x0 fit: hosting / ISP / shared network (' || ind.industry || ')'
                       when ind.industry in {tuple(REGULATED)} then 'x{REGULATED_FIT} fit: regulated industry (' || ind.industry || ')'
                       when ind.industry is null then 'fit not classified' end] as reasons
          from cs join worst using (company)
          left join {industry_source} ind using (company)
        )
        select * replace (list_filter(reasons, x -> x is not null) as reasons),
               round(need * urgency, 3) as priority_before_fit,
               round(need * urgency * fit, 3) as priority
        from s
        order by priority desc, risky_ips desc""")

    print(con.sql("""
        with b as (select is_landlord, ips, row_number() over (order by priority_before_fit desc, risky_ips desc) rk from scored),
             a as (select is_landlord, ips, row_number() over (order by priority desc, risky_ips desc) rk from scored)
        select 'before Fit' as ranking, round(100 * avg(coalesce(is_landlord, false)::int), 1) as landlord_pct_top100,
               round(avg(ips), 1) as avg_ips_top100 from b where rk <= 100
        union all
        select 'after Fit', round(100 * avg(coalesce(is_landlord, false)::int), 1), round(avg(ips), 1) from a where rk <= 100"""))

    print(con.sql("""
        select count(*) as companies, count(*) filter (where priority > 0) as with_need,
               round(quantile_cont(priority, 0.5), 2) as median, round(max(priority), 2) as max
        from scored"""))
    print(con.sql("""
        with r as (select *, row_number() over (order by priority desc, risky_ips desc) as rk from scored)
        select case when rk <= 100 then 'top 100' when rk <= 1000 then 'top 1000' else 'rest' end as band,
               round(avg(ips), 1) as avg_ips
        from r group by 1 order by min(rk)"""))
    print(con.sql("select company, country, industry, ips, risky_ips, priority, reasons from scored limit 15"))
    con.sql(f"copy scored to '{(DATA / 'scored_companies.parquet').as_posix()}' (format parquet, compression zstd)")


if __name__ == "__main__":
    main()
