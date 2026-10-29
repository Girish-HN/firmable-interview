"""Stage 3 (File Gate): decide whether a Scan File is fit to reach sellers, before anything downstream uses it.

One streaming pass runs cheap checks on 100% of Banners. Each check is BLOCK (stop this file: sellers keep the
previous results) or WARN (continue, with the reason recorded). A seeded random sample of 300 Banners is saved for
a person to spot-check: if 1% of Banners were bad, all 300 would look fine only 0.99^300 = 5% of the time,
whatever the file size.

Drift checks compare against a baseline: the metrics of the last accepted file. The first file has no baseline,
so drift checks report "no baseline" and the file becomes the baseline once accepted.

Usage:
  python scripts/file_gate.py check <scan_file.zst|.jsonl> [--report docs/file-gate-report.md] [--no-baseline-update]
  python scripts/file_gate.py review <file_stem>    # after filling the 'issue' column of the sample CSV
Writes data/gate/<file_stem>.json (metrics, checks, decision) and data/gate/<file_stem>.sample.csv.
Exit code: 0 PASS, 1 WARN, 2 BLOCK.
"""
import argparse
import csv
import json as stdjson
import datetime as dt
import hashlib
import io
import json
import random
import sys
import time
from collections import Counter
from pathlib import Path

import os

import orjson
import zstandard

ROOT = Path(__file__).resolve().parent.parent
GATE_DIR = Path(os.environ.get("FILE_GATE_DIR", ROOT / "data" / "gate"))  # tests point this at a temp folder
BASELINE = GATE_DIR / "baseline.json"
SAMPLE_SIZE = 300

REQUIRED = ["ip", "port", "transport", "timestamp"]  # every Banner needs these to mean anything
# Schema contract: fields the pipeline reads, with the minimum share of Banners that must carry them.
# Floors sit well below what one real file shows (in brackets) so that only a broken feed trips them.
CONTRACT = {
    "location": 0.95,   # 100%: server country
    "_shodan": 0.95,    # 100%: scanner module
    "org": 0.90,        # 100%: Landlord detection
    "hostnames": 0.50,  # 100%: attribution (reverse DNS)
    "domains": 0.50,    # 74%: attribution
    "tags": 0.20,       # 71%: honeypots, end-of-life, exposure tags
    "http": 0.05,       # 29.5%: titles, headers, WAF
    "ssl": 0.005,       # 6.8%: certificate attribution and expiry
    "vulns": 0.002,     # 3.2%: CVEs, KEV, EPSS
}
LIMITS = {
    "parse_error_block": 0.001,   # >0.1% unparseable lines: truncated or corrupt file
    "required_block": 0.01,       # >1% of Banners missing a required field
    "invalid_block": 0.01,        # >1% with an impossible port or unreadable timestamp
    "scan_days_warn": 2,          # one file should cover about one scan day
    "volume_warn": (0.6, 1.67),   # Banner count vs baseline
    "fill_drift_warn": 0.30,      # relative change in a contract field's fill rate vs baseline
    "share_drift_warn": 0.50,     # relative change in the share with CVEs / honeypots vs baseline
    "country_drift_warn": 0.15,   # total variation distance of the country mix vs baseline
}


class HashingReader(io.RawIOBase):
    """Wraps the compressed file so its SHA-256 is computed in the same pass (the file's identity in the manifest)."""

    def __init__(self, f):
        self.f, self.sha = f, hashlib.sha256()

    def readable(self):
        return True

    def readinto(self, b):
        n = self.f.readinto(b)
        if n:
            self.sha.update(memoryview(b)[:n])
        return n


def open_lines(path, raw):
    if path.suffix == ".zst":
        return io.TextIOWrapper(zstandard.ZstdDecompressor(max_window_size=2**31).stream_reader(raw),
                                encoding="utf-8", errors="replace")
    return io.TextIOWrapper(raw, encoding="utf-8", errors="replace")


def sample_row(line_no, r):
    http = r.get("http") or {}
    cert = ((r.get("ssl") or {}).get("cert") or {}).get("subject") or {}
    return {
        "line": line_no, "ip": r.get("ip_str") or r.get("ipv6"), "port": r.get("port"),
        "timestamp": r.get("timestamp"), "org": r.get("org"), "domains": " ".join(r.get("domains") or []),
        "cert_cn": cert.get("CN"), "product": r.get("product"), "title": (http.get("title") or "")[:120],
        "tags": " ".join(r.get("tags") or []), "cves": len(r.get("vulns") or {}),
        "issue": "",  # reviewer fills this in: blank = looks fine, otherwise describe the problem
    }


def scan(path, max_lines=None):
    """One pass: collect the metrics every check needs, plus a reservoir sample of SAMPLE_SIZE Banners."""
    rng = random.Random(path.name)  # seeded by file name: re-running a file draws the same sample
    m = {"lines": 0, "parse_errors": 0, "fallback_parsed": 0, "bad_lines": [], "missing": Counter(), "invalid": Counter(), "present": Counter(),
         "keys": Counter(), "days": Counter(), "countries": Counter(), "with_vulns": 0, "honeypots": 0,
         "ts_min": None, "ts_max": None}
    sample = []
    with open(path, "rb") as f:
        raw = HashingReader(f)
        for line_no, line in enumerate(open_lines(path, io.BufferedReader(raw, 1 << 20)), 1):
            if max_lines and line_no > max_lines:
                break
            m["lines"] += 1
            try:
                r = orjson.loads(line)
            except ValueError as fast_error:
                # orjson is stricter than the JSON spec (e.g. integers beyond 64 bits): retry before calling it corrupt
                try:
                    r = stdjson.loads(line)
                    m["fallback_parsed"] += 1
                except ValueError as error:
                    r = None
                    fast_error = error
                if r is None:
                    m["parse_errors"] += 1
                    if len(m["bad_lines"]) < 5:
                        m["bad_lines"].append({"line": line_no, "error": str(fast_error)[:120], "length": len(line)})
                    continue
            if not isinstance(r, dict):
                m["parse_errors"] += 1
                continue
            m["keys"].update(r.keys())
            if not (r.get("ip_str") or r.get("ipv6") or r.get("ip") is not None):
                m["missing"]["ip"] += 1
            for key in ("port", "transport", "timestamp"):
                if r.get(key) in (None, ""):
                    m["missing"][key] += 1
            port = r.get("port")
            if port is not None and not (isinstance(port, int) and 0 <= port <= 65535):
                m["invalid"]["port"] += 1
            ts = r.get("timestamp")
            if isinstance(ts, str) and ts:
                try:
                    dt.datetime.fromisoformat(ts)
                    m["days"][ts[:10]] += 1
                    m["ts_min"] = min(m["ts_min"] or ts, ts)
                    m["ts_max"] = max(m["ts_max"] or ts, ts)
                except ValueError:
                    m["invalid"]["timestamp"] += 1
            m["countries"][(r.get("location") or {}).get("country_code")] += 1
            m["with_vulns"] += bool(r.get("vulns"))
            m["honeypots"] += "honeypot" in (r.get("tags") or [])
            # reservoir sampling: every parsed Banner has the same chance of being in the sample
            parsed = m["lines"] - m["parse_errors"]
            if len(sample) < SAMPLE_SIZE:
                sample.append(sample_row(line_no, r))
            elif (j := rng.randrange(parsed)) < SAMPLE_SIZE:
                sample[j] = sample_row(line_no, r)
        # finish reading so the checksum covers the whole file even when max_lines stopped early
        if not max_lines:
            while raw.read(1 << 20):
                pass
    m["sha256"] = raw.sha.hexdigest() if not max_lines else None
    m["countries"] = dict(m["countries"].most_common(60))
    m["present"] = {k: m["keys"].get(k, 0) for k in CONTRACT}
    for key in ("missing", "invalid", "keys", "days"):
        m[key] = dict(m[key])
    return m, sample


def result(name, level, ok, observed, threshold, why):
    return {"check": name, "level": level, "status": "PASS" if ok else level,
            "observed": observed, "threshold": threshold, "why": why}


def run_checks(m, baseline):
    parsed = max(m["lines"] - m["parse_errors"], 1)
    rate = lambda count, total=parsed: count / total
    checks = [
        result("parse_errors", "BLOCK", rate(m["parse_errors"], max(m["lines"], 1)) <= LIMITS["parse_error_block"],
               f"{m['parse_errors']:,} of {m['lines']:,} lines ({rate(m['parse_errors'], max(m['lines'], 1)):.3%})"
               + (f"; {m['fallback_parsed']:,} valid only under the standard JSON parser" if m["fallback_parsed"] else ""),
               f"≤ {LIMITS['parse_error_block']:.1%}", "Unparseable lines mean a truncated or corrupt file."),
        result("parse_errors_any", "WARN", m["parse_errors"] == 0,
               f"{m['parse_errors']:,}" + "".join(f"; line {b['line']:,} ({b['length']:,} chars): {b['error']}"
                                                   for b in m["bad_lines"][:2]), "0",
               "Even a few bad lines are worth a look (often a cut-off last line)."),
    ]
    for key in REQUIRED:
        miss = m["missing"].get(key, 0)
        checks.append(result(f"required_{key}", "BLOCK", rate(miss) <= LIMITS["required_block"],
                             f"{miss:,} missing ({rate(miss):.2%})", f"≤ {LIMITS['required_block']:.0%}",
                             f"Without `{key}` a Banner can't be placed or scored."))
    for key in ("port", "timestamp"):
        bad = m["invalid"].get(key, 0)
        checks.append(result(f"valid_{key}", "BLOCK", rate(bad) <= LIMITS["invalid_block"],
                             f"{bad:,} invalid ({rate(bad):.2%})", f"≤ {LIMITS['invalid_block']:.0%}",
                             "Ports must be 0–65535 and timestamps ISO-8601."))
    broken = {k: rate(m["present"].get(k, 0)) for k, floor in CONTRACT.items() if rate(m["present"].get(k, 0)) < floor}
    checks.append(result("schema_contract", "BLOCK", not broken,
                         ", ".join(f"{k} {v:.2%}" for k, v in broken.items()) or "all fields above their floors",
                         "fill ≥ floor for " + ", ".join(CONTRACT),
                         "A field the pipeline depends on vanished or was renamed upstream."))
    today = dt.date.today().isoformat()
    days = sorted(m["days"])
    checks.append(result("scan_window", "WARN", len(days) <= LIMITS["scan_days_warn"] and (not days or days[-1] <= today),
                         f"{len(days)} day(s): {days[0]} → {days[-1]}" if days else "no timestamps",
                         f"≤ {LIMITS['scan_days_warn']} days, none in the future",
                         "One file is one scan day; more, or future dates, means a mixed or mislabelled file."))

    if not baseline:
        checks.append(result("drift_vs_baseline", "WARN", False, "no baseline (first file)", "a previously accepted file",
                             "Volume and distribution drift can't be judged on the first file; it becomes the baseline."))
        return checks
    b_parsed = max(baseline["lines"] - baseline["parse_errors"], 1)
    new = {k: v for k, v in m["keys"].items() if k not in baseline["keys"] and rate(v) >= 0.01}
    checks.append(result("schema_new_fields", "WARN", not new,
                         ", ".join(f"{k} ({rate(v):.1%})" for k, v in sorted(new.items())) or "none",
                         "no field on ≥ 1% of Banners that the baseline never had",
                         "Not harmful by itself, but often a rename of something we read."))
    gone = [k for k, v in baseline["keys"].items() if v / b_parsed >= 0.05 and k not in m["keys"]]
    checks.append(result("schema_fields_vanished", "WARN", not gone, ", ".join(sorted(gone)) or "none",
                         "every field on ≥ 5% of baseline Banners still present",
                         "A field disappearing upstream; the contract BLOCKs only for fields the score reads."))
    ratio = parsed / b_parsed
    lo, hi = LIMITS["volume_warn"]
    checks.append(result("volume", "WARN", lo <= ratio <= hi, f"{parsed:,} Banners ({ratio:.2f}× baseline)",
                         f"{lo}–{hi}× baseline", "A much smaller file suggests a scanner outage or partial delivery."))
    drifted = []
    for k in CONTRACT:
        now, before = rate(m["present"].get(k, 0)), baseline["present"].get(k, 0) / b_parsed
        if before and abs(now - before) / before > LIMITS["fill_drift_warn"]:
            drifted.append(f"{k} {before:.1%}→{now:.1%}")
    checks.append(result("fill_drift", "WARN", not drifted, ", ".join(drifted) or "all within limit",
                         f"≤ {LIMITS['fill_drift_warn']:.0%} relative change", "Fields filling much less often than usual."))
    for key, label in (("with_vulns", "Banners with CVEs"), ("honeypots", "honeypots")):
        now, before = rate(m[key]), baseline[key] / b_parsed
        change = abs(now - before) / before if before else 0
        checks.append(result(f"share_{key}", "WARN", change <= LIMITS["share_drift_warn"],
                             f"{before:.2%} → {now:.2%}", f"≤ {LIMITS['share_drift_warn']:.0%} relative change",
                             f"A jump in {label} shifts scores for every Company."))
    p = {k: v / parsed for k, v in m["countries"].items()}
    q = {k: v / b_parsed for k, v in baseline["countries"].items()}
    tvd = 0.5 * sum(abs(p.get(k, 0) - q.get(k, 0)) for k in set(p) | set(q))
    checks.append(result("country_mix", "WARN", tvd <= LIMITS["country_drift_warn"], f"distance {tvd:.3f}",
                         f"≤ {LIMITS['country_drift_warn']}", "A different country mix means a different slice of the internet was scanned."))
    return checks


def decide(checks):
    statuses = {c["status"] for c in checks}
    return "BLOCK" if "BLOCK" in statuses else "WARN" if "WARN" in statuses else "PASS"


def write_report(path, stem, m, checks, decision, seconds):
    icon = {"PASS": "✅ PASS", "WARN": "⚠️ WARN", "BLOCK": "⛔ BLOCK"}
    lines = [f"# File Gate report: `{stem}`", "",
             f"**Decision: {icon[decision]}** · {m['lines']:,} lines · {seconds / 60:.1f} min · "
             f"SHA-256 `{(m['sha256'] or 'not computed (partial run)')[:16]}…`", "",
             "Reproduce: `python scripts/file_gate.py check data/raw/dataset.zst --report docs/file-gate-report.md`. "
             "BLOCK stops the file from reaching sellers (exit code 2); WARN continues with the reason recorded.", "",
             "## Checks on 100% of Banners", "", "| Check | Level | Result | Observed | Threshold | Why it matters |",
             "|---|---|---|---|---|---|"]
    for c in checks:
        lines.append(f"| `{c['check']}` | {c['level']} | {icon[c['status']]} | {c['observed']} | {c['threshold']} | {c['why']} |")
    parsed = max(m["lines"] - m["parse_errors"], 1)
    lines += ["", "## Schema contract: fill rates", "", "| Field | Fill | Floor |", "|---|---|---|"]
    lines += [f"| `{k}` | {m['present'].get(k, 0) / parsed:.1%} | {floor:.1%} |" for k, floor in CONTRACT.items()]
    lines += ["", "## Human spot-check", "",
              f"{SAMPLE_SIZE} Banners were drawn at random (seeded by file name, so re-runs draw the same ones) into "
              f"`data/gate/{stem}.sample.csv`. A reviewer reads each row, writes any problem in the `issue` column "
              f"(garbled text, impossible values, a title that contradicts the domain), then runs "
              f"`python scripts/file_gate.py review {stem}`. Zero issues in {SAMPLE_SIZE} rows means the defect rate is "
              f"below 1% with 95% confidence (rule of three: 3 / {SAMPLE_SIZE}), whatever the file size. The sample stays "
              f"out of the repository because it contains real IP addresses.", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def check(args):
    path = Path(args.scan_file).resolve()
    stem = path.name.split(".")[0]
    GATE_DIR.mkdir(parents=True, exist_ok=True)
    baseline = json.loads(BASELINE.read_text()) if BASELINE.exists() and not args.ignore_baseline else None
    t0 = time.time()
    m, sample = scan(path, args.max_lines)
    checks = run_checks(m, baseline)
    decision = decide(checks)
    seconds = time.time() - t0

    (GATE_DIR / f"{stem}.json").write_text(json.dumps(
        {"file": str(path), "decision": decision, "checked_at": dt.datetime.now().isoformat(timespec="seconds"),
         "seconds": round(seconds, 1), "metrics": m, "checks": checks}, indent=1, default=str), encoding="utf-8")
    with open(GATE_DIR / f"{stem}.sample.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(sample[0]) if sample else ["line"])
        writer.writeheader()
        writer.writerows(sorted(sample, key=lambda r: r["line"]))
    if args.report:
        write_report(Path(args.report), stem, m, checks, decision, seconds)
    if decision != "BLOCK" and not args.no_baseline_update and not args.max_lines:
        BASELINE.write_text(json.dumps({k: m[k] for k in ("lines", "parse_errors", "present", "keys", "countries",
                                                          "with_vulns", "honeypots")} | {"file": str(path)}))

    for c in checks:
        print(f"  {c['status']:5}  {c['check']:20} {c['observed']}")
    print(f"{decision}: {path.name} ({m['lines']:,} lines, {seconds / 60:.1f} min)")
    return {"PASS": 0, "WARN": 1, "BLOCK": 2}[decision]


def review(args):
    """Turn the reviewer's verdicts on the sample into a defect-rate estimate with a 95% upper bound."""
    with open(GATE_DIR / f"{args.stem}.sample.csv", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    issues = [r for r in rows if r["issue"].strip()]
    n, k = len(rows), len(issues)
    # 95% upper bound: rule of three for zero defects, else a normal approximation (adequate at n = 300)
    upper = 3 / n if k == 0 else k / n + 1.96 * (k / n * (1 - k / n) / n) ** 0.5
    print(f"{k} issue(s) in {n} sampled Banners: defect rate {k / n:.1%}, 95% upper bound {upper:.1%}")
    for r in issues[:20]:
        print(f"  line {r['line']}: {r['issue']}")
    verdict = "BLOCK" if upper > 0.05 else "WARN" if k else "PASS"
    print(f"spot-check verdict: {verdict} (BLOCK if the upper bound exceeds 5%)")
    return {"PASS": 0, "WARN": 1, "BLOCK": 2}[verdict]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("scan_file")
    c.add_argument("--report")
    c.add_argument("--max-lines", type=int, help="stop early (testing only; skips the checksum and baseline update)")
    c.add_argument("--no-baseline-update", action="store_true")
    c.add_argument("--ignore-baseline", action="store_true")
    r = sub.add_parser("review")
    r.add_argument("stem")
    args = parser.parse_args()
    sys.exit(check(args) if args.cmd == "check" else review(args))


if __name__ == "__main__":
    main()
