# Security Leads: finding companies that need cybersecurity help, from internet scan data

**App:** https://firmable-security-leads.streamlit.app/ (protected by an access token shared with reviewers, see [Data handling](#data-handling))

A sales tool for a cybersecurity vendor. It reads one day of Shodan internet-scan data (17.6 GB, 14.6 M service
banners), works out which company each exposed server belongs to, and ranks companies by how much they need
security help, how urgently, and how well they fit as a buyer. Every score comes with the evidence behind it and
talking points a seller can use.

## Approach

```
Scan File → Parse → Clean → Signals → Attribute → Roll up → Score → Validate → Serve
 17.6 GB     slim     honeypots,   23 rules   banner →    one row     Need ×      Golden    Streamlit
 zstd        Parquet  tarpits,     per        company     per         Urgency ×   Set       app
                      landlords    banner     (domain)    company     Fit
```

**Rules where rules work; an LLM only where meaning is needed** ([ADR-0002](docs/adr/0002-llm-only-where-meaning-is-needed.md)).
Signals and scores are SQL rules: reproducible, cheap and auditable. Claude is used for one job a rule can't do:
reading a company's page titles and certificates to decide what it does, and whether it is a hosting provider or
ISP whose servers mostly belong to its customers.

**A company is a registrable domain, and is never guessed** ([ADR-0001](docs/adr/0001-company-is-registrable-domain.md)).
`org` names whoever owns the IP address: Incapsula alone is 32% of all banners and Google 22%. So banners are tied
to companies through TLS certificates, HTTP host names, leaked Windows domains and reverse DNS. Only 6.2% of
banners can be attributed this way; the rest are counted, not guessed, because a wrong guess sends a seller to the
wrong company with a scary claim.

## The hidden signals, and how they were proved

23 candidate signals were tested on all 362,572 attributable companies. The yardstick is CISA's list of actively
exploited vulnerabilities (KEV): **lift** = how much more often companies with a signal also have a KEV CVE.
Bigger footprints show more of everything, so lift is recomputed on single-IP companies to remove size as an
explanation ([full table](docs/signal-analysis.md)).

| Hidden signal | Where it hides | Lift (single-IP) |
|---|---|---|
| Outdated runtime (PHP ≤ 7.3, old ASP.NET) | `X-Powered-By` header in the raw banner | **4.7×** |
| Default server page ("Welcome to nginx!") | page title | **2.4×** |
| Site unchanged for 3+ years | `Last-Modified` header in the raw banner | **2.0×** |
| Web application firewall present | `http.waf` | **0.1×** (a maturity marker: lowers Need) |

Default pages and stale sites matter most: they carry no version number, so their lift can't be an echo of
Shodan's version-based CVE matching. They're independent evidence of neglect. Five intuitive signals were
**dropped because the data disproved them**, including `security.txt` (expected to mark maturity; 1.3× instead),
self-signed certificates and legacy TLS (both ≈1×). Exposed Remote Desktop and databases score ~0× because they
rarely reveal a version, so KEV can't see them; they're kept with a moderate weight justified by CISA ransomware
guidance instead.

## Scoring

**Priority = Need × Urgency × Fit**, multiplied so that one disqualifying factor (e.g. a hosting provider) sinks the score.

- **Need:** points from the riskiest server's findings. Weights are ln(single-IP lift), measured rather than
  hand-tuned (KEV CVE +2.06, end-of-life software +1.72, outdated runtime +1.56; WAF −2.34). An early version
  summed findings across all servers and ranked hosting companies first simply because they own more servers.
- **Urgency:** why call this week: signs of compromise, a CVE used in ransomware campaigns, a claimable
  subdomain, a certificate expiring within 30 days.
- **Fit:** 0 for hosting providers and ISPs (their riskiest server is a customer's), 1.25 for regulated industries
  (healthcare, finance, legal, education, government), else 1.0.

## How we know it works

A **Golden Set** of 150 companies, stratified as top 50, middle 50 and random 50, labelled for industry,
hosting-provider status, attribution correctness and "would a seller call them?" Labels were researched per
company with Google Gemini (a different model family from Claude, with web access) and entered by hand, with every
model–label disagreement checked by a person. 20 rows were labelled **blind** (no pre-fill shown) to measure
anchoring: agreement was higher on blind rows (95%) than pre-filled ones (86%), so there was no sign of it.

The hosting-provider decision drives Fit, so it was iterated against the Golden Set ([full report](docs/evaluation.md)):

| Version | Precision | Recall | Outcome |
|---|---|---|---|
| v1: Haiku 5.5 | 75% | 82% | baseline |
| v3: Haiku 5.5, rewritten prompt | 81% | 67% | **rejected**: fixed universities, but stopped catching ISPs |
| Sonnet 5.5, v1 prompt (same evidence) | 89% | 76% | better, at 19× the cost |
| **v5: Haiku v1 on all + Sonnet on the top 300** | **89%** | **73%** | **production** |

In the top 50, v5 surfaces 13 credible leads where v1 surfaced 9, and wrongly removes 1 where v1 removed 5.
Both models miss the same hosting providers, because nothing in the scan says "we sell hosting": a bigger model
can't see what isn't in the evidence. That points to the next improvement (below).

Two other checks: Haiku's run-to-run consistency (12% of answers flipped on near-identical evidence before inputs
were canonicalised; now cached and reproducible), and the caveat that v3–v5 were designed after seeing errors on
this same set, so their numbers are optimistic until confirmed on fresh companies.

## What it costs

| | |
|---|---|
| Total LLM spend to build and evaluate | **$4.05** (every call logged in `data/processed/llm_calls.jsonl`) |
| Production, per Scan File (v5) | **≈ $1.71**: Haiku on 5,000 companies ($0.15 / 1k) + Sonnet on the top 300 ($3.14 / 1k) |
| At 1,000 files a month | ≈ $1,700 in LLM calls; results are cached by evidence hash, so unchanged companies cost nothing |

## Scaling to thousands of files a month

Parse, clean and signal extraction only ever look at one file, so files run in parallel on as many workers as
there are files (≈ 18 single-core minutes per file today, about 300 core-hours for 1,000 files). Company-level
roll-up merges per-file results incrementally instead of reprocessing history. LLM calls scale with *new or
changed* companies, not banners. See [system design](docs/system-design.md).

**Every file passes a File Gate before it can reach sellers** ([`scripts/file_gate.py`](scripts/file_gate.py),
[report on the real file](docs/file-gate-report.md)). One streaming pass checks 100% of banners. BLOCK checks
stop the file: parse errors, missing required fields, impossible values, and a schema contract for every field the
score reads. WARN checks let it through with the reason recorded: volume, scan window, new or vanished fields,
and drift in the CVE share, honeypot share and country mix against the last accepted file. Extraction refuses a
file the gate blocked or never saw. A seeded 300-banner sample goes to a person, which catches a 1% defect rate
with 95% probability regardless of file size (0.99³⁰⁰ ≈ 0.05). The `review` command turns their verdicts into a
defect-rate bound. [`scripts/test_file_gate.py`](scripts/test_file_gate.py) proves each check fires by gating
eleven deliberately broken copies of real data (truncated, corrupted, renamed fields, missing CVE data, shifted
dates, partial volume, country and CVE drift).

## v5 is the baseline: the information gap

The system works end to end; these are the measured next steps, in order of expected value:

1. **Network ownership.** If a company owns the network its servers sit on, it is almost certainly an ISP or host.
   A free text match on data already extracted lifts recall from 73% to 85% on the Golden Set (optimistic: the
   rule was designed after seeing the misses).
2. **Unattributed exposures.** Only 10% of exposed Remote Desktop servers name their owner. Joining IP ranges to a
   company database (Firmable's core data) is the biggest lever on recall.
3. **Signals extracted but not yet scored:** Heartbleed (35 companies; a live test, not an inferred CVE), exposed
   firewall/router/Exchange management interfaces (~2,100), SMB (343) and cameras (1,811). Exclude malware/C2 hosts
   (7) like honeypots.
4. **Fresh evaluation companies**, to measure v5 without the bias of having tuned on the Golden Set.

## How it was built

AI-native, with the data understood first. The full file was profiled before any modelling: every column's fill
rate, the landlord trap, honeypots, tarpits. Decisions were recorded as ADRs and a [glossary](GLOSSARY.md) so the
coding agent (Claude Code) and the human used the same words. Every LLM step had a measurement before it had a
second version: the prompt rewrite that looked better was rejected because the Golden Set said so.

## Running it

```bash
pip install -r requirements.txt polars zstandard orjson tldextract anthropic python-dotenv
python scripts/file_gate.py check data/raw/dataset.zst --report docs/file-gate-report.md   # ~20 min
python scripts/test_file_gate.py      # 11 broken-file cases (needs data/sample/sample.jsonl from scripts/sample.py)
python scripts/extract_banners.py      # 17.6 GB scan file → data/processed/banners.parquet (~37 min)
python scripts/analyze_signals.py      # attribution, signal prevalence and lift
python scripts/score.py                # Need × Urgency (Fit once industry.parquet exists)
python scripts/classify_industry.py    # Haiku 5.5 on the top 5,000 (needs ANTHROPIC_API_KEY in .env)
python scripts/cascade.py              # v5: Sonnet 5.5 re-checks the top 300
python scripts/score.py                # re-score with Fit
python scripts/eval_golden.py          # Golden Set evaluation → docs/evaluation.md
python scripts/export_app_data.py      # small tables for the app
streamlit run app/streamlit_app.py     # needs ACCESS_TOKEN = "..." in .streamlit/secrets.toml
```

## Data handling

The app and its data name real organisations alongside their exposed services and exploitable CVEs. Although
Shodan data is publicly collected, the aggregated list is a ready-made target list. So the repository is
private, and the app opens to a token prompt: nothing (no data, no page) renders until the shared access token is
entered, and a deployment without the token configured shows nothing at all. The token lives in the host's
secrets store and a git-ignored `.streamlit/secrets.toml`, never in the code; it is checked with a constant-time
comparison. The raw scan file, the Golden Set labels and the LLM cache are not in the repository.
