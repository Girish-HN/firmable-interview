"""Single streaming pass over the full Shodan banner file, collecting distribution stats.

Writes data/processed/profile.json and logs progress every 1M records.
Usage: python scripts/profile.py [max_records]
"""
import io
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

import zstandard

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATASET_PATH = os.environ.get("DATASET_PATH", str(DATA_DIR / "raw" / "dataset.zst"))
OUT_PATH = DATA_DIR / "processed" / "profile.json"
TOP = 200


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
    c = {name: Counter() for name in [
        "keys", "port", "country", "org", "tags", "product", "module",
        "vulns", "domain", "transport", "http_status", "waf", "day",
    ]}
    n = with_domain = with_vulns = ssl_expired = parse_errors = 0
    ips = set()
    t0 = time.time()

    with open(DATASET_PATH, "rb") as f:
        reader = zstandard.ZstdDecompressor(max_window_size=2**31).stream_reader(f)
        for line in io.TextIOWrapper(reader, encoding="utf-8", errors="replace"):
            if limit and n >= limit:
                break
            try:
                r = json.loads(line)
            except ValueError:
                parse_errors += 1
                continue
            n += 1
            c["keys"].update(r.keys())
            c["port"][r.get("port")] += 1
            c["country"][(r.get("location") or {}).get("country_code")] += 1
            c["org"][r.get("org")] += 1
            c["tags"].update(r.get("tags") or [])
            c["product"][r.get("product")] += 1
            c["module"][(r.get("_shodan") or {}).get("module")] += 1
            c["transport"][r.get("transport")] += 1
            c["day"][(r.get("timestamp") or "")[:10]] += 1
            if r.get("ip_str"):
                ips.add(r["ip_str"])
            domains = r.get("domains") or []
            if domains:
                with_domain += 1
                c["domain"].update(domains)
            vulns = r.get("vulns") or {}
            if vulns:
                with_vulns += 1
                c["vulns"].update(vulns if isinstance(vulns, list) else vulns.keys())
            http = r.get("http")
            if http:
                c["http_status"][http.get("status")] += 1
                c["waf"][http.get("waf")] += 1
            if ((r.get("ssl") or {}).get("cert") or {}).get("expired"):
                ssl_expired += 1
            if n % 1_000_000 == 0:
                rate = n / (time.time() - t0)
                print(f"{n:,} records, {rate:,.0f}/s, {len(c['domain']):,} domains", flush=True)

    out = {
        "records": n,
        "parse_errors": parse_errors,
        "seconds": round(time.time() - t0, 1),
        "distinct_ips": len(ips),
        "distinct_domains": len(c["domain"]),
        "distinct_orgs": len(c["org"]),
        "distinct_cves": len(c["vulns"]),
        "with_domain": with_domain,
        "with_vulns": with_vulns,
        "ssl_expired": ssl_expired,
        "top": {k: [[str(key), cnt] for key, cnt in v.most_common(TOP)] for k, v in c.items()},
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"done: {n:,} records in {out['seconds']}s -> {OUT_PATH}")


if __name__ == "__main__":
    main()
