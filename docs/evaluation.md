# Evaluation

Reproduce: `python scripts/golden_set.py` (sample + Opus pre-fills), label `data/golden/golden_labels.csv` by hand, then `python scripts/eval_golden.py`.

Golden Set: 150 Companies (50 top-ranked before Fit, 50 mid-ranked, 50 random with Need > 0); 150 labelled, 20 of them blind (no pre-fill shown). Labels were researched per Company with Google Gemini (a different model family from Claude, with web access to the live sites) and entered by hand: independent of Claude, but AI-assisted rather than purely human.

## 1. Landlord detection (drives Fit = 0)

| Model | Precision | Recall | n |
|---|---|---|---|
| Claude Haiku 5.5, prompt v1 | 75% | 82% | 61 |
| Claude Haiku 5.5, prompt v3 (rejected) | 81% | 67% | 61 |
| v5: Haiku v1 + Sonnet 5.5 on the top 300 (production) | 89% | 73% | 61 |
| Claude Opus 5.5 (pre-fill) | 95% | 70% | 150 |

v5 (production) is a rule fixed before it was evaluated: Haiku 5.5 with prompt v1 classifies the top 5,000 Companies, and Sonnet 5.5 with the same prompt and evidence re-checks the top 300 by pre-Fit priority (the ones most likely to reach a seller), replacing Haiku's answer. Every top-stratum Golden Set Company is in that top 300; middle and random rows keep Haiku's answer, as in production.

Prompt v3 adds rules for single universities and SaaS companies (not Landlords) and city education networks (Landlords), and drops generic page titles ("301 Moved Permanently") from the evidence so the informative ones fit. It was written after reading the v1 errors on this same set, so its numbers are optimistic; a fresh sample would give an unbiased estimate.

Same prompt (v1) and identical evidence, on the Golden Set Companies both models classified:

| Model | Precision | Recall | Industry accuracy | USD per 1,000 Companies | n |
|---|---|---|---|---|---|
| Claude Haiku 5.5 | 75% | 82% | 59% | $0.17 | 61 |
| Claude Sonnet 5.5 | 89% | 76% | 64% | $3.25 | 61 |

Both models miss the same thin-evidence ISPs and hosts (e.g. teletek.net.tr, syncwave.net, 5july.net): the clue isn't in the scan data, so a bigger model can't see it either.

Industry exact-match accuracy (Haiku v1 vs. labels): **59%** over 61 Companies.  
Industry exact-match accuracy (Haiku v3 vs. labels): **66%** over 61 Companies.  
Industry exact-match accuracy (v5 vs. labels): **62%** over 61 Companies.  
(Haiku only classified the top 5,000, so random-stratum rows are partly uncovered.)

## 2. Anchoring check

| Rows | Labels agree with Opus: landlord | credible lead | n |
|---|---|---|---|
| pre-filled | 86% | 72% | 130 |
| blind (no pre-fill) | 95% | 84% | 19 |

Agreement much higher on pre-filled rows than blind ones would mean the pre-fills anchored the labels; the blind rows are then the more trustworthy measure. Excluded: 1 blind row(s) discussed with Claude during labelling.

## 3. Ranking quality

| Stratum | Credible leads (labels) | Landlords (labels) | n |
|---|---|---|---|
| top | 28% | 58% | 50 |
| middle | 50% | 30% | 50 |
| random | 48% | 24% | 50 |

Within the pre-Fit top 50:

| Version | Kept by Fit: credible leads | n | Removed by Fit (Fit = 0): correctly not leads | n |
|---|---|---|---|---|
| Haiku v1 | 56% | 16 | 85% | 34 |
| Haiku v3 | 48% | 25 | 92% | 25 |
| v5 | 52% | 25 | 96% | 25 |

## 4. Run-to-run consistency

1,059 Companies were classified twice by Haiku on near-identical evidence (an early cache-key bug: list order and tie-breaks varied between runs). The landlord flag flipped for **130** (12.3%) and the industry for 216 (20.4%). Evidence is now canonicalised, so a re-run makes zero calls and reproduces the same labels.

## 5. Cost

| Step | Model | Calls | USD |
|---|---|---|---|
| industry | `claude-haiku-5-5` | 11,773 | $1.960 |
| golden_prefill | `claude-opus-5-5` | 150 | $1.112 |
| industry_sonnet | `claude-sonnet-5-5` | 250 | $0.777 |
| model_compare | `claude-sonnet-5-5` | 61 | $0.198 |
| smoke_test | `claude-haiku-5-5` | 1 | $0.000 |

Total spent: **$4.05**, including prompt v1, the rejected v3 (two small trials and a full re-run) and the Sonnet comparison. Production (v5) per Scan File: Haiku 5.5 on 5,000 Companies at $0.153 per 1,000, plus Sonnet 5.5 on the top 300 at $3.14 per 1,000: **about $1.71 per file**.
