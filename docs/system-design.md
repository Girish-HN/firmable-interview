# System design

Capitalised terms (Banner, Company, Signal…) are defined in [GLOSSARY.md](../GLOSSARY.md).
Key decisions: [ADR-0001](adr/0001-company-is-registrable-domain.md) (what a Company is),
[ADR-0002](adr/0002-llm-only-where-meaning-is-needed.md) (where LLMs are used).

## The problem in numbers

| | One Scan File (measured) | Production (brief) |
|---|---|---|
| Size | 17.6 GB zstd | hundreds–thousands of files / month |
| Banners | 14.6 M | ~5–15 B / month (~0.2–0.5 B / day) |
| Distinct IPs / domains | 4.9 M / 488 k | n/a |
| Single-pass parse time (laptop, 1 core) | ~18 min | parallel across files |

## Pipeline

```
 Scan Files (.zst)
   │
 ① LAND       manifest per file (checksum, size, Banner count); idempotent
   │
 ② PARSE      stream-decompress → keep useful fields + raw-banner extracts → Parquet, partitioned by file
   │
 ③ FILE GATE  checks on 100% of Banners (parse errors, null rates, schema drift, distribution drift)
   │          each check is BLOCK or WARN; ~300-Banner random sample per file for spot checks
   │
 ④ SIGNALS    deterministic rules per Banner; Honeypots dropped
   │
 ⑤ ATTRIBUTE  Banner → Registrable Domain (rules first; LLM only for the ambiguous tail)
   │          + LLM industry classification per Company
   │
 ⑥ ROLL UP    one row per Company: footprint, Signals, Evidence, country, industry
   │
 ⑦ SCORE      Priority Score = f(Need, Fit, Urgency), computed, with human-readable reasons
   │
 ⑧ VALIDATE   Golden Set (~200 Companies): Attribution & industry precision/recall,
   │          top-k ranking quality, LLM cost per 1k Companies; re-run on every prompt/model change
   │
 ⑨ SERVE      precomputed Parquet/DuckDB → Streamlit: ranked Companies, filters, Evidence page
```

## Why each stage looks like this

- **① Land / ② Parse.** Files are independent, so ①–④ run per file in parallel and re-running a file is a no-op.
  The raw HTML is only reduced to extracts (title, security headers, `Last-Modified`), because it is large and,
  as Windows Defender showed during profiling, can contain live phishing kits.
- **③ File Gate.** Volume makes per-Banner human review impossible, so quality is a budget problem. Cheap checks
  run on everything. A fixed-size random sample per file gives a guaranteed detection floor: with ~300 samples, a
  1% defect rate is caught with 95% confidence (P(miss) = 0.99^300 ≈ 5%), independent of file size. A failing
  BLOCK check stops the file's results reaching sellers; WARN checks ship with a recorded reason.
- **④ Signals.** Rules, not an LLM (ADR-0002). Candidate Signals include KEV CVEs (and ransomware use), high-EPSS
  CVEs, end-of-life software, exposed Remote Desktop / databases / ICS / medical devices, expired or weak TLS,
  missing security headers, default/stale pages, and the `compromised` tag. The final list is chosen from profiling evidence.
- **⑤ Attribute.** Certificate subject and HTTP host are the most trustworthy identity behind a Landlord.
  Unattributed Banners are counted, not guessed (ADR-0001).
- **⑦ Score.** A single snapshot has no history, so Urgency uses what is visible now (actively exploited CVEs,
  certificates about to expire, signs of compromise). Every Banner carries its scan date, so a second file yields
  "new since last scan" without a schema change.
- **⑧ Validate.** Precision/recall on the Golden Set, measured before and after any prompt or model change, is
  how we know the LLM steps are right and what they cost.

## Scoring and validation decisions

- **Weights are evidence-based points.** For Signals validated by lift ([signal-analysis.md](signal-analysis.md)), weight = ln(single-IP lift), so outdated runtime (4.7×) ≈ +1.5 and a WAF (0.1×) ≈ −2.3. Exposure Signals that lift can't measure get a fixed moderate weight justified by CISA and incident-response sources. Every Priority Score decomposes into its contributing Signals, so a seller sees why.
- **Need comes from a Company's riskiest IP, not its whole footprint.** The first version took the union of Signals across all IPs, and the top 100 averaged 24 IPs vs. 1.7 overall: small hosting providers and ISPs won by owning more servers. Scoring per IP and taking the maximum cut the top-100 average to 11.7 IPs. The number of risky IPs is shown as context, not added as points.
- **Hosting providers, ISPs and shared academic networks get Fit = 0**, decided by the LLM industry classification. Their riskiest server is usually a customer's, which no rule can see from a Banner; recognising "this is a hosting company" from its pages is a meaning task (ADR-0002). The Golden Set measures the Landlord share of the top 50 before and after.
  *As built:* Claude Haiku 5.5 classified the 5,000 highest-Need Companies for $0.15 per 1,000; the Landlord share
  of the top 100 fell from 57% to 0% and the top-100 average footprint from 11.7 to 3.9 IPs. Accuracy against the
  Golden Set is in [evaluation.md](evaluation.md).
- **LLM results are cached by a hash of canonical evidence.** An early version built evidence from SQL lists in
  arbitrary order (and a tie-broken "most common country"), so identical Companies got new cache keys and were
  re-classified: about 1,060 repeats, at a cost of ~$0.26. Sorting before slicing fixed it; a re-run now makes zero calls.
  The accidental repeats became a consistency measurement (evaluation.md section 4).
- **Fit is mostly a seller-controlled filter** (industry, country, footprint size), plus a modest built-in boost for regulated industries (healthcare, finance, legal, education). The brief names no target segment, so none is hard-coded.
- **Golden Set:** ~150 Companies stratified as top 50 by score, 50 random and 50 from the middle. Labels: attribution correct (y/n), industry, credible lead (y/n).
  Claude Opus 5.5 pre-fills, a human verifies, and Claude Haiku 5.5's bulk industry labels are scored against the verified set (precision, recall, cost per 1k Companies).
- **LLM budget:** hard cap of $5 (a $5 prepaid top-up plus a matching Console spend limit). Estimated spend is $2–3: Haiku 5.5 at $0.10 / $0.50 per MTok for ~5,000 Companies ≈ $0.65, plus ~$1.50 of Opus 5.5 pre-labels.
  DeepSeek was priced as an alternative (Flash $0.15 / $0.60 per MTok off-peak) and rejected: no cheaper for the bulk job, and only ~$1 cheaper overall.

## Scaling from one file to thousands a month

The demo processes one Scan File end to end. In production, ①–④ run as one job per file on a worker pool
(at ~18 single-core minutes per file, 1,000 files ≈ 300 core-hours/month). ⑤–⑦ merge per-file Company
aggregates incrementally rather than reprocessing history. LLM calls are bounded by deduplicating on Company,
not Banner, and by caching results keyed on Registrable Domain + page hash.
