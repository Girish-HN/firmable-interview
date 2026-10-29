"""Stage 9 (Serve): export the small, precomputed tables the Streamlit app reads.

The app never touches the 400 MB Banner files: it reads the Companies the LLM classified (the ranked set a
seller works from) and their Banners, each tagged with the Signals it triggered. Both files are small enough
to commit, so the hosted app needs no data pipeline of its own.

Usage: python scripts/export_app_data.py
Writes app/data/accounts.parquet and app/data/evidence.parquet
"""
from pathlib import Path

import duckdb

from analyze_signals import SIGNALS
from score import EXPOSURE, LABELS, LIFT_WEIGHTED, CVE_FAMILY, MATURITY, URGENCY

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "processed"
OUT = ROOT / "app" / "data"

# Only the Signals the score uses; dropped ones (legacy TLS, self-signed...) would confuse a seller.
SCORED = CVE_FAMILY + LIFT_WEIGHTED + MATURITY + EXPOSURE + list(URGENCY)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()
    con.sql(f"""
        create table accounts as
        select s.company, s.country, s.industry, s.is_landlord, s.industry_evidence, i.model as classified_by,
               s.ips, s.risky_ips, s.worst_ip, s.need::double as need, s.urgency::double as urgency,
               s.fit::double as fit, s.priority_before_fit::double as priority_before_fit,
               s.priority::double as priority, s.reasons
        from '{(DATA / 'scored_companies.parquet').as_posix()}' s
        join '{(DATA / 'industry.parquet').as_posix()}' i using (company)""")
    con.sql(f"copy accounts to '{(OUT / 'accounts.parquet').as_posix()}' (format parquet, compression zstd)")

    flags = ", ".join(f"case when {SIGNALS[n]} then '{LABELS[n]}' end" for n in SCORED)
    con.sql(f"""
        create table evidence as
        select company, ip, port, module, product, version, title, server_header, x_powered_by, org,
               country, attributed_by, kev_cves, ransomware_cves, max_cvss, max_epss, cert_expires, waf,
               last_modified, list_filter([{flags}], x -> x is not null) as signals
        from '{(DATA / 'attributed.parquet').as_posix()}'
        where company in (select company from accounts)
        -- a service can be seen more than once in a scan day; a seller needs it once
        qualify row_number() over (partition by company, ip, port order by len(signals) desc) = 1""")
    con.sql(f"copy evidence to '{(OUT / 'evidence.parquet').as_posix()}' (format parquet, compression zstd)")

    for name in ("accounts", "evidence"):
        n = con.sql(f"select count(*) from {name}").fetchone()[0]
        size = (OUT / f"{name}.parquet").stat().st_size / 1e6
        print(f"{name}: {n:,} rows, {size:.1f} MB")


if __name__ == "__main__":
    main()
