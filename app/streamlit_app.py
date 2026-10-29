"""Security Leads: ranked Companies likely to need cybersecurity software, with the evidence behind each one.

Reads the precomputed tables in app/data (scripts/export_app_data.py) and docs/evaluation.md; no LLM calls.
Run locally: streamlit run app/streamlit_app.py
"""
from pathlib import Path

import duckdb
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(__file__).resolve().parent / "data"

st.set_page_config(page_title="Security Leads", page_icon="🛡️", layout="wide")


@st.cache_data
def load_accounts():
    df = duckdb.sql(f"select * from '{(DATA / 'accounts.parquet').as_posix()}'").df()
    df = df.sort_values(["priority", "priority_before_fit"], ascending=False).reset_index(drop=True)
    df["rank"] = range(1, len(df) + 1)
    df["top_finding"] = df["reasons"].map(lambda r: r[0].split(" ", 1)[1] if len(r) else "")
    return df


@st.cache_data
def load_evidence():
    return duckdb.sql(f"select * from '{(DATA / 'evidence.parquet').as_posix()}'").df()


SIGNAL_OPTIONS = [
    "actively exploited CVE (CISA KEV)", "CVE used in ransomware campaigns", "end-of-life software",
    "outdated PHP / ASP.NET", "Remote Desktop open to the internet", "database open to the internet",
    "Telnet / VNC open to the internet", "industrial or medical device exposed", "default server page left exposed",
    "website unchanged for 3+ years", "open directory listing", "expired TLS certificate",
    "TLS certificate expires within 30 days", "subdomain takeover possible", "signs of compromise",
]


# ---------------------------------------------------------------- talking points
def talking_points(account, evidence):
    """Templated, evidence-backed lines a seller can use. Strongest finding first, at most four."""
    ev = evidence[evidence["signals"].map(len) > 0]
    points = []

    def first(label):
        rows = ev[ev["signals"].map(lambda s: label in s)]
        return None if rows.empty else rows.iloc[0]

    def where(r):
        return f"{r['ip']}:{r['port']}"

    def software(r):
        return " ".join(str(x) for x in (r["product"], r["version"]) if pd.notna(x) and x) or "a service"

    if (r := first("signs of compromise")) is not None:
        points.append(f"**Already compromised?** {where(r)} shows signs of a breach (Shodan tag). Raise it carefully and early.")
    if (r := first("actively exploited CVE (CISA KEV)")) is not None:
        cves = ", ".join(r["kev_cves"][:2])
        ransom = " CISA also links it to ransomware campaigns." if len(r["ransomware_cves"]) else ""
        points.append(f"**Actively exploited flaw:** {software(r)} on {where(r)} matches {cves}, which CISA lists as "
                      f"exploited in the wild.{ransom}")
    if (r := first("Remote Desktop open to the internet")) is not None:
        points.append(f"**Remote Desktop exposed:** {where(r)} accepts Remote Desktop connections from anywhere, "
                      "one of the most common ransomware entry points.")
    if (r := first("database open to the internet")) is not None:
        points.append(f"**Database exposed:** a database on {where(r)} answers from the open internet.")
    if (r := first("Telnet / VNC open to the internet")) is not None:
        points.append(f"**Remote access exposed:** Telnet/VNC on {where(r)} is reachable from the internet.")
    if (r := first("industrial or medical device exposed")) is not None:
        points.append(f"**Device exposed:** an industrial or medical system on {where(r)} is reachable from the internet.")
    if (r := first("end-of-life software")) is not None:
        points.append(f"**Unsupported software:** {software(r)} on {where(r)} is past end-of-life and gets no security patches.")
    if (r := first("outdated PHP / ASP.NET")) is not None:
        points.append(f"**Outdated runtime:** {where(r)} reports `{r['x_powered_by']}`, a version that no longer gets fixes.")
    if (r := first("default server page left exposed")) is not None:
        points.append(f"**Forgotten server:** {where(r)} shows a default \"{r['title']}\" page: set up and never finished.")
    if (r := first("website unchanged for 3+ years")) is not None:
        points.append(f"**Stale site:** the site on {where(r)} hasn't changed since {pd.Timestamp(r['last_modified']):%Y}.")
    if (r := first("subdomain takeover possible")) is not None:
        points.append(f"**Takeover risk:** a hostname on {where(r)} points at an unclaimed service anyone could register.")
    if (r := first("TLS certificate expires within 30 days")) is not None:
        points.append(f"**Why now:** the certificate on {where(r)} expires on {pd.Timestamp(r['cert_expires']):%d %b %Y}.")
    if (r := first("expired TLS certificate")) is not None:
        points.append(f"**Visible neglect:** the certificate on {where(r)} has expired; visitors see a browser warning.")
    points = points[:4]
    if (r := first("already behind a web application firewall")) is not None:
        points.append(f"**Positioning:** they already run a web application firewall ({r['waf']}), so pitch as "
                      "complementing existing tooling, not replacing it.")
    return points


# ---------------------------------------------------------------- pages
def accounts_page():
    st.title("Accounts")
    st.caption("Companies ranked by Priority = Need × Urgency × Fit, from one Shodan scan (2026-10-26). "
               "Click a row to open the account.")
    df = load_accounts()

    with st.sidebar:
        st.header("Filters")
        query = st.text_input("Company contains")
        industries = st.multiselect("Industry", sorted(df["industry"].dropna().unique()))
        countries = st.multiselect("Server country", sorted(df["country"].dropna().unique()))
        signals = st.multiselect("Has finding (all of)", SIGNAL_OPTIONS)
        show_landlords = st.toggle("Include hosting providers / ISPs (Fit = 0)", value=False)

    view = df
    if not show_landlords:
        view = view[view["fit"] > 0]
    if query:
        view = view[view["company"].str.contains(query.strip().lower(), regex=False)]
    if industries:
        view = view[view["industry"].isin(industries)]
    if countries:
        view = view[view["country"].isin(countries)]
    for s in signals:
        view = view[view["reasons"].map(lambda r, s=s: any(s in x for x in r))]

    c1, c2, c3 = st.columns(3)
    c1.metric("Accounts shown", f"{len(view):,}")
    c2.metric("With an actively exploited CVE",
              f"{view['reasons'].map(lambda r: any('CISA KEV' in x for x in r)).sum():,}")
    c3.metric("Regulated industries", f"{view['industry'].isin(['healthcare', 'finance', 'legal', 'education', 'government']).sum():,}")

    table = view[["rank", "company", "industry", "country", "priority", "top_finding", "risky_ips", "ips"]]
    event = st.dataframe(
        table, hide_index=True, width="stretch", height=560, on_select="rerun", selection_mode="single-row",
        column_config={
            "rank": st.column_config.NumberColumn("Rank", width="small"),
            "company": "Company", "industry": "Industry", "country": "Country",
            "priority": st.column_config.ProgressColumn("Priority", format="%.1f", min_value=0,
                                                        max_value=float(df["priority"].max())),
            "top_finding": "Top finding",
            "risky_ips": st.column_config.NumberColumn("Risky IPs", help="IPs with at least one finding"),
            "ips": st.column_config.NumberColumn("IPs seen"),
        })
    if event.selection.rows:
        st.session_state["company"] = table.iloc[event.selection.rows[0]]["company"]
        st.switch_page(DETAIL)


def detail_page():
    df = load_accounts()
    companies = df["company"].tolist()
    current = st.session_state.get("company", companies[0])
    company = st.selectbox("Account", companies, index=companies.index(current) if current in companies else 0)
    st.session_state["company"] = company
    a = df[df["company"] == company].iloc[0]
    ev = load_evidence()
    ev = ev[ev["company"] == company].copy()
    ev["n"] = ev["signals"].map(len)
    ev = ev.sort_values(["n", "ip", "port"], ascending=[False, True, True])

    st.title(company)
    landlord = " · **hosting provider / ISP (Fit = 0)**" if a["is_landlord"] else ""
    st.markdown(f"**{(a['industry'] or 'unknown').replace('_', ' ')}** · servers in {a['country']} · "
                f"rank #{a['rank']:,} of {len(df):,}{landlord}")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Priority", f"{a['priority']:.1f}")
    c2.metric("Need", f"{a['need']:.2f}", help="Points from the riskiest IP's findings")
    c3.metric("Urgency", f"×{a['urgency']:.2f}", help="Why-now multiplier")
    c4.metric("Fit", f"×{a['fit']:.2f}", help="0 for hosting providers / ISPs, 1.25 for regulated industries")

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Talking points")
        points = talking_points(a, ev)
        for p in points or ["No findings on attributed servers."]:
            st.markdown(f"- {p}")
        st.caption("CVEs are inferred by Shodan from software versions, not tested; confirm before quoting them as fact.")
    with right:
        st.subheader("Why this score")
        for r in a["reasons"]:
            st.markdown(f"- `{r.split(' ', 1)[0]}` {r.split(' ', 1)[1]}")
        st.subheader("Who they are")
        model = {"claude-haiku-5-5": "Claude Haiku 5.5", "claude-sonnet-5-5": "Claude Sonnet 5.5"}.get(a["classified_by"], a["classified_by"])
        st.markdown(f"Classified by **{model}** from page titles, certificates and server software:")
        st.info(a["industry_evidence"])

    st.subheader(f"Evidence: {len(ev):,} services on {ev['ip'].nunique():,} IPs "
                 f"({a['risky_ips']} with findings)")
    st.dataframe(
        ev[["ip", "port", "product", "version", "title", "signals", "kev_cves", "max_cvss", "max_epss", "attributed_by"]],
        hide_index=True, width="stretch",
        column_config={
            "ip": "IP", "port": st.column_config.NumberColumn("Port", format="%d"), "product": "Software",
            "version": "Version", "title": "Page title",
            "signals": st.column_config.ListColumn("Findings"),
            "kev_cves": st.column_config.ListColumn("KEV CVEs"),
            "max_cvss": st.column_config.NumberColumn("Max CVSS", format="%.1f"),
            "max_epss": st.column_config.NumberColumn("Max EPSS", format="%.2f"),
            "attributed_by": st.column_config.TextColumn("Linked to company by",
                                                         help="Which field tied this server to the company"),
        })


def evaluation_page():
    st.title("How we know it works")
    df = load_accounts()
    st.markdown("""
**Pipeline.** One 17.6 GB Shodan file (14.6 M service banners, 4.9 M IPs) → honeypots, tarpits and hosting
providers' own domains removed → each banner tied to a company through its certificate, web host name or reverse
DNS (6.2% can be; the rest are counted, never guessed) → 23 candidate signals tested against CISA's list of
actively exploited flaws, controlling for footprint size → **Priority = Need × Urgency × Fit**, where Fit comes
from Claude classifying each company's industry and whether it is a hosting provider or ISP.

**Rules where rules work, an LLM only where meaning is needed.** Signals and scores are computed and
reproducible; Claude only reads page titles and certificates to decide *who* a company is.
""")
    c1, c2, c3 = st.columns(3)
    c1.metric("Companies classified", f"{len(df):,}")
    c2.metric("Removed as hosting / ISP", f"{(df['fit'] == 0).sum():,}")
    c3.metric("Re-checked by Sonnet 5.5", f"{(df['classified_by'] == 'claude-sonnet-5-5').sum():,}")
    st.divider()
    st.markdown((ROOT / "docs" / "evaluation.md").read_text(encoding="utf-8"))


ACCOUNTS = st.Page(accounts_page, title="Accounts", icon="📋", default=True)
DETAIL = st.Page(detail_page, title="Account detail", icon="🔎")
EVALUATION = st.Page(evaluation_page, title="How we know it works", icon="📏")
st.navigation([ACCOUNTS, DETAIL, EVALUATION]).run()
