"""Extract the first N records of the zstd-compressed Shodan banner file into browsable files.

Writes:
  data/sample/sample.jsonl  - raw records, one JSON per line (open in VS Code)
  data/sample/sample.csv    - key fields flattened (open in Excel)

Usage: python scripts/sample.py [N]   (default 5000)
Dataset path comes from DATASET_PATH, defaulting to data/raw/dataset.zst.
"""
import csv
import io
import json
import os
import sys
from pathlib import Path

import zstandard

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATASET_PATH = os.environ.get("DATASET_PATH", str(DATA_DIR / "raw" / "dataset.zst"))
OUT_DIR = DATA_DIR / "sample"

CSV_FIELDS = [
    "timestamp", "ip_str", "port", "transport", "product", "version",
    "hostnames", "domains", "org", "isp", "asn",
    "country_code", "city",
    "http_status", "http_title", "http_server", "http_waf",
    "ssl_expired", "ssl_versions", "vulns", "tags",
]


def iter_records(path):
    with open(path, "rb") as f:
        reader = zstandard.ZstdDecompressor(max_window_size=2**31).stream_reader(f)
        for line in io.TextIOWrapper(reader, encoding="utf-8", errors="replace"):
            if line.strip():
                yield json.loads(line)


def flatten(r):
    http = r.get("http") or {}
    ssl = r.get("ssl") or {}
    loc = r.get("location") or {}
    vulns = r.get("vulns") or (r.get("opts") or {}).get("vulns") or {}
    return {
        "timestamp": r.get("timestamp"),
        "ip_str": r.get("ip_str"),
        "port": r.get("port"),
        "transport": r.get("transport"),
        "product": r.get("product"),
        "version": r.get("version"),
        "hostnames": ";".join(r.get("hostnames") or []),
        "domains": ";".join(r.get("domains") or []),
        "org": r.get("org"),
        "isp": r.get("isp"),
        "asn": r.get("asn"),
        "country_code": loc.get("country_code"),
        "city": loc.get("city"),
        "http_status": http.get("status"),
        "http_title": http.get("title"),
        "http_server": http.get("server"),
        "http_waf": http.get("waf"),
        "ssl_expired": (ssl.get("cert") or {}).get("expired"),
        "ssl_versions": ";".join(ssl.get("versions") or []),
        "vulns": ";".join(vulns if isinstance(vulns, list) else vulns.keys()),
        "tags": ";".join(r.get("tags") or []),
    }


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_DIR / "sample.jsonl", "w", encoding="utf-8") as fj, \
         open(OUT_DIR / "sample.csv", "w", encoding="utf-8-sig", newline="") as fc:
        writer = csv.DictWriter(fc, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for i, r in enumerate(iter_records(DATASET_PATH)):
            if i >= n:
                break
            fj.write(json.dumps(r, ensure_ascii=False) + "\n")
            writer.writerow(flatten(r))
    print(f"wrote {min(i, n)} records to {OUT_DIR}")


if __name__ == "__main__":
    main()
