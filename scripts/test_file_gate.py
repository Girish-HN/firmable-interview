"""Prove each File Gate check fires: build deliberately broken copies of a real sample and gate each one.

Needs data/sample/sample.jsonl (5,000 real Banners from scripts/sample.py). Runs in a temporary folder under
data/, so the real baseline in data/gate is never touched.

Usage: python scripts/test_file_gate.py
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "sample" / "sample.jsonl"
GATE = ROOT / "scripts" / "file_gate.py"


def rows():
    with open(SAMPLE, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def write(path, records, raw_tail=""):
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write((r if isinstance(r, str) else json.dumps(r)) + "\n")
        f.write(raw_tail)


def gate(path, workdir, *flags):
    env = os.environ | {"FILE_GATE_DIR": str(workdir), "PYTHONIOENCODING": "utf-8"}
    out = subprocess.run([sys.executable, str(GATE), "check", str(path), *flags], capture_output=True, text=True, env=env)
    out_file = Path(workdir) / f"{path.stem}.json"
    if not out_file.exists():
        raise RuntimeError(f"gate crashed on {path.name}: {out.stderr[-2000:]}")
    result = json.loads(out_file.read_text(encoding="utf-8"))
    return out.returncode, result


def failing(result):
    return {c["check"]: c["status"] for c in result["checks"] if c["status"] != "PASS"}


def main():
    clean = rows()
    # inside data/: the sample holds a real phishing page that antivirus blocks in the system temp folder
    with tempfile.TemporaryDirectory(dir=ROOT / "data") as tmp:
        tmp = Path(tmp)
        cases = []

        def case(name, records, expect_decision, expect_check, raw_tail="", flags=()):
            path = tmp / f"{name}.jsonl"
            write(path, records, raw_tail)
            code, result = gate(path, tmp, *flags)
            fired = failing(result)
            ok = result["decision"] == expect_decision and (expect_check is None or expect_check in fired)
            cases.append((name, expect_decision, expect_check, result["decision"], code, fired, ok))

        # 1. A clean file sets the baseline (first file: drift can't be judged yet, so it WARNs, never BLOCKs).
        case("clean_first_file", clean, "WARN", "drift_vs_baseline")
        # 2. The same clean data again, now with a baseline: every check passes.
        case("clean_with_baseline", clean, "PASS", None, flags=("--no-baseline-update",))
        # 3. A download cut off mid-line: one bad line is tolerated but flagged.
        case("truncated_last_line", clean, "WARN", "parse_errors_any",
             raw_tail=json.dumps(clean[0])[:80], flags=("--no-baseline-update",))
        # 4. Corruption: 5% of lines are garbage.
        garbage = [r if i % 20 else "\x00\x13garbage{" for i, r in enumerate(clean)]
        case("garbage_lines", garbage, "BLOCK", "parse_errors", flags=("--no-baseline-update",))
        # 5. Upstream renames a required field.
        renamed = [{("port_number" if k == "port" else k): v for k, v in r.items()} for r in clean]
        case("port_renamed", renamed, "BLOCK", "required_port", flags=("--no-baseline-update",))
        # 6. Upstream drops a field the score depends on (CVEs).
        no_vulns = [{k: v for k, v in r.items() if k != "vulns"} for r in clean]
        case("vulns_dropped", no_vulns, "BLOCK", "schema_contract", flags=("--no-baseline-update",))
        # 7. Impossible values.
        bad_ports = [r | {"port": 99999} if i % 10 == 0 else r for i, r in enumerate(clean)]
        case("invalid_ports", bad_ports, "BLOCK", "valid_port", flags=("--no-baseline-update",))
        # 8. Mislabelled file: timestamps spread over a week, some in the future.
        shifted = [r | {"timestamp": f"2027-0{1 + i % 7}-0{1 + i % 7}T00:00:00"} for i, r in enumerate(clean)]
        case("dates_shifted", shifted, "WARN", "scan_window", flags=("--no-baseline-update",))
        # 9. Partial delivery: a third of the usual volume.
        case("partial_volume", clean[:1500], "WARN", "volume", flags=("--no-baseline-update",))
        # 10. A different slice of the internet: every Banner geolocated to one country.
        one_country = [r | {"location": (r.get("location") or {}) | {"country_code": "BR"}} for r in clean]
        case("country_drift", one_country, "WARN", "country_mix", flags=("--no-baseline-update",))
        # 11. CVE data suddenly on far more Banners (e.g. a changed matching rule upstream).
        donor = next(r["vulns"] for r in clean if r.get("vulns"))
        cve_spike = [r | {"vulns": r.get("vulns") or donor} if i % 4 == 0 else r for i, r in enumerate(clean)]
        case("cve_share_spike", cve_spike, "WARN", "share_with_vulns", flags=("--no-baseline-update",))

    width = max(len(c[0]) for c in cases)
    print(f"{'case':{width}}  expected        got     exit  fired")
    for name, exp_d, exp_c, got, code, fired, ok in cases:
        mark = "ok  " if ok else "FAIL"
        print(f"{mark} {name:{width}}  {exp_d:5} {exp_c or '':18} {got:5}  {code}  {', '.join(f'{k}={v}' for k, v in fired.items())}")
    failed = [c for c in cases if not c[-1]]
    print(f"\n{len(cases) - len(failed)}/{len(cases)} cases behaved as expected")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
