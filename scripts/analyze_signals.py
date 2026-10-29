"""Signal analysis over data/processed/banners.parquet (output of extract_banners.py).

1. Landlord domains: candidate domains spread over many IPs (clouds, CDNs, ISPs), or packing many hostnames onto
   few services (multi-tenant platforms such as website builders), are hosting providers, not Companies.
   Tarpit IPs answering on hundreds of ports are dropped as noise.
2. Attribution: Banner -> Company (Registrable Domain), in priority order cert > http host > ntlm > rDNS.
3. Signal prevalence: Banners and Companies hit by each candidate Signal.
4. Lift: how much more often a Company with each Signal also has a KEV CVE (does a hidden Signal track real risk?).

Usage: python scripts/analyze_signals.py
Writes data/processed/{landlords,attributed,company_signals}.parquet and prints the tables.
"""
from pathlib import Path

import duckdb

DATA = Path(__file__).resolve().parent.parent / "data" / "processed"
SCAN_DATE = "2026-10-26"
LANDLORD_MIN_IPS = 50  # a candidate domain on this many distinct IPs is a hosting provider
MULTI_TENANT_MIN_BANNERS_PER_SERVICE = 20  # many hostnames scanned on one IP:port = a shared platform
TARPIT_MIN_PORTS = 100  # an IP answering on this many ports is a scanner trap, not a real footprint

SIGNALS = {
    # obvious
    "kev_cve": "len(kev_cves) > 0",
    "ransomware_cve": "len(ransomware_cves) > 0",
    "critical_cvss": "max_cvss >= 9",
    "high_epss": "max_epss >= 0.5",
    "eol_software": "list_has_any(tags, ['eol-product', 'eol-os'])",
    "exposed_rdp": "port = 3389 or list_contains(protocol_blocks, 'rdp_encryption')",
    "exposed_database": "list_contains(tags, 'database') or port in (3306, 5432, 1433, 27017, 6379, 9200)",
    "exposed_remote_shell": "port in (23, 5900) or list_has_any(protocol_blocks, ['telnet', 'vnc'])",
    "ics_or_medical": "list_has_any(tags, ['ics', 'medical'])",
    "compromised": "list_has_any(tags, ['compromised', 'doublepulsar'])",
    "cert_expired": "cert_expired",
    "open_directory": "list_contains(tags, 'open-dir')",
    # hidden
    "takeover_candidate": "takeover is not null",
    "cert_expiring_30d": f"not cert_expired and cert_expires < timestamp '{SCAN_DATE}' + interval 30 day",
    "stale_site_3y": f"last_modified < timestamp '{SCAN_DATE}' - interval 3 year",
    "default_page": """regexp_matches(lower(coalesce(title, '')),
        'welcome to nginx|iis windows server|apache2 .* default page|default web site page|it works!|test page for')""",
    "outdated_runtime": """regexp_matches(coalesce(x_powered_by, ''), 'PHP/(5\\.|7\\.[0-3])|ASP\\.NET [1-3]\\.')""",
    "legacy_tls": "len(tls_legacy) > 0",
    "self_signed": "cert_self_signed",
    "exposed_login_portal": """regexp_matches(lower(coalesce(title, '')),
        'fortinet|fortigate|globalprotect|citrix|netscaler|pulse secure|sonicwall|outlook web|owa|vpn|remote desktop web')""",
    # maturity (lowers Need)
    "has_waf": "waf is not null",
    "has_security_txt": "has_securitytxt",
    "has_hsts": "has_hsts",
}


def main():
    con = duckdb.connect()
    con.sql(f"create view banners as select * from '{(DATA / 'banners.parquet').as_posix()}'")

    con.sql(f"""
        create table tarpits as
        select ip from banners group by ip having count(distinct port) >= {TARPIT_MIN_PORTS}""")
    con.sql(f"""
        create table landlords as
        with d as (
          select unnest([cert_domain, http_host_domain, ntlm_domain] || rdns_domains) as domain, ip, port, org
          from banners
        )
        select domain, count(distinct ip) as ips, count(*) as banners,
               round(count(*) / count(distinct (ip, port)), 1) as banners_per_service, any_value(org) as example_org,
               case when count(distinct ip) >= {LANDLORD_MIN_IPS} then 'many_ips' else 'multi_tenant' end as reason
        from d where domain is not null
        group by domain
        having count(distinct ip) >= {LANDLORD_MIN_IPS}
            or count(*) / count(distinct (ip, port)) >= {MULTI_TENANT_MIN_BANNERS_PER_SERVICE}
        order by ips desc""")
    print("Tarpit IPs:", con.sql("select count(*) from tarpits").fetchone()[0])
    print(con.sql("select reason, count(*) as domains from landlords group by 1"))
    print(con.sql("select * from landlords where reason = 'multi_tenant' order by banners desc limit 15"))

    # Attribution: first trustworthy candidate wins; Landlord domains never count as a Company.
    con.sql("""
        create table attributed as
        with base as (
          select row_number() over () as banner_id, *
          from banners
          where not list_contains(tags, 'honeypot') and ip not in (select ip from tarpits)
        ),
        candidates as (
          select banner_id,
            unnest([cert_domain, http_host_domain, ntlm_domain] || rdns_domains) as domain,
            unnest(['cert', 'http_host', 'ntlm'] || list_transform(rdns_domains, x -> 'rdns')) as source,
            unnest(range(3 + len(rdns_domains))) as priority
          from base
        ),
        picked as (
          select banner_id, arg_min(domain, priority) as company, arg_min(source, priority) as attributed_by
          from candidates
          where domain is not null and domain not in (select domain from landlords)
          group by banner_id
        )
        select base.*, picked.company, picked.attributed_by
        from base left join picked using (banner_id)""")
    print(con.sql("""
        select coalesce(attributed_by, 'UNATTRIBUTED') as attributed_by, count(*) as banners,
               round(100.0 * count(*) / sum(count(*)) over (), 1) as pct
        from attributed group by 1 order by 2 desc"""))
    print("Companies:", con.sql("select count(distinct company) from attributed").fetchone()[0])

    flags = ",\n".join(f"bool_or(coalesce({expr}, false)) as {name}" for name, expr in SIGNALS.items())
    con.sql(f"""
        create table company_signals as
        select company, count(distinct (ip, port)) as services, count(distinct ip) as ips,
               mode(country) as country, {flags}
        from attributed where company is not null group by company""")
    n = con.sql("select count(*) from company_signals").fetchone()[0]

    # Lift = P(KEV | signal) / P(KEV). Bigger footprints have more chances of both, so it is also
    # computed among single-IP Companies only, where footprint size can't explain it.
    base_kev, base_kev_1ip = con.sql("""
        select avg(kev_cve::int), avg(kev_cve::int) filter (where ips = 1) from company_signals""").fetchone()
    print(f"\n{n:,} Companies; baseline KEV rate {base_kev:.2%} (single-IP: {base_kev_1ip:.2%})\n")
    print(f"{'signal':24} {'companies':>10} {'% of cos':>9} {'KEV lift':>9} {'1-IP lift':>10}")
    for name in SIGNALS:
        hit, kev_rate, kev_rate_1ip = con.sql(f"""
            select sum({name}::int), avg(kev_cve::int) filter (where {name}),
                   avg(kev_cve::int) filter (where {name} and ips = 1)
            from company_signals""").fetchone()
        lift = (kev_rate or 0) / base_kev
        lift_1ip = (kev_rate_1ip or 0) / base_kev_1ip
        print(f"{name:24} {hit or 0:>10,} {100 * (hit or 0) / n:>8.2f}% {lift:>8.1f}x {lift_1ip:>9.1f}x")

    for table in ("landlords", "attributed", "company_signals"):
        con.sql(f"copy {table} to '{(DATA / f'{table}.parquet').as_posix()}' (format parquet, compression zstd)")


if __name__ == "__main__":
    main()
