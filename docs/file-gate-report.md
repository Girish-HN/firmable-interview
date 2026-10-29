# File Gate report: `dataset`

**Decision: ⚠️ WARN** · 14,608,407 lines · 10.1 min · SHA-256 `71cb1991955ae585…`

Reproduce: `python scripts/file_gate.py check data/raw/dataset.zst --report docs/file-gate-report.md`. BLOCK stops the file from reaching sellers (exit code 2); WARN continues with the reason recorded.

## Checks on 100% of Banners

| Check | Level | Result | Observed | Threshold | Why it matters |
|---|---|---|---|---|---|
| `parse_errors` | BLOCK | ✅ PASS | 0 of 14,608,407 lines (0.000%); 1 valid only under the standard JSON parser | ≤ 0.1% | Unparseable lines mean a truncated or corrupt file. |
| `parse_errors_any` | WARN | ✅ PASS | 0 | 0 | Even a few bad lines are worth a look (often a cut-off last line). |
| `required_ip` | BLOCK | ✅ PASS | 0 missing (0.00%) | ≤ 1% | Without `ip` a Banner can't be placed or scored. |
| `required_port` | BLOCK | ✅ PASS | 0 missing (0.00%) | ≤ 1% | Without `port` a Banner can't be placed or scored. |
| `required_transport` | BLOCK | ✅ PASS | 0 missing (0.00%) | ≤ 1% | Without `transport` a Banner can't be placed or scored. |
| `required_timestamp` | BLOCK | ✅ PASS | 0 missing (0.00%) | ≤ 1% | Without `timestamp` a Banner can't be placed or scored. |
| `valid_port` | BLOCK | ✅ PASS | 0 invalid (0.00%) | ≤ 1% | Ports must be 0–65535 and timestamps ISO-8601. |
| `valid_timestamp` | BLOCK | ✅ PASS | 0 invalid (0.00%) | ≤ 1% | Ports must be 0–65535 and timestamps ISO-8601. |
| `schema_contract` | BLOCK | ✅ PASS | all fields above their floors | fill ≥ floor for location, _shodan, org, hostnames, domains, tags, http, ssl, vulns | A field the pipeline depends on vanished or was renamed upstream. |
| `scan_window` | WARN | ✅ PASS | 2 day(s): 2026-10-25 → 2026-10-26 | ≤ 2 days, none in the future | One file is one scan day; more, or future dates, means a mixed or mislabelled file. |
| `drift_vs_baseline` | WARN | ⚠️ WARN | no baseline (first file) | a previously accepted file | Volume and distribution drift can't be judged on the first file; it becomes the baseline. |

## Schema contract: fill rates

| Field | Fill | Floor |
|---|---|---|
| `location` | 100.0% | 95.0% |
| `_shodan` | 100.0% | 95.0% |
| `org` | 100.0% | 90.0% |
| `hostnames` | 100.0% | 50.0% |
| `domains` | 100.0% | 50.0% |
| `tags` | 71.0% | 20.0% |
| `http` | 29.5% | 5.0% |
| `ssl` | 6.8% | 0.5% |
| `vulns` | 3.2% | 0.2% |

## Human spot-check

300 Banners were drawn at random (seeded by file name, so re-runs draw the same ones) into `data/gate/dataset.sample.csv`. A reviewer reads each row, writes any problem in the `issue` column (garbled text, impossible values, a title that contradicts the domain), then runs `python scripts/file_gate.py review dataset`. Zero issues in 300 rows means the defect rate is below 1% with 95% confidence (rule of three: 3 / 300), whatever the file size. The sample stays out of the repository because it contains real IP addresses.
