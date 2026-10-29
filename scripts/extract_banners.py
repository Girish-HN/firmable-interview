"""Stage 2 (Parse): stream one Scan File into a slim Banner table for signal analysis.

One row per Banner, keeping only attribution fields and raw inputs to Signals. Flags that need
the raw HTML are computed here (the HTML itself is dropped); everything else is derived in SQL later.

Refuses to run on a file the File Gate blocked or never checked (scripts/file_gate.py).

Usage: python scripts/extract_banners.py [max_banners]
Writes data/processed/banners.parquet
"""
import io
import os
import sys
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from functools import lru_cache
from pathlib import Path

import orjson
import pyarrow as pa
import pyarrow.parquet as pq
import tldextract
import zstandard

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATASET_PATH = Path(os.environ.get("DATASET_PATH", DATA_DIR / "raw" / "dataset.zst"))
OUT_PATH = DATA_DIR / "processed" / "banners.parquet"
FLUSH_EVERY = 250_000

# Body text served when a DNS name points at a deprovisioned cloud resource: a subdomain-takeover candidate.
TAKEOVER_MARKERS = {
    "NoSuchBucket": "aws_s3",
    "The specified bucket does not exist": "aws_s3",
    "There isn't a GitHub Pages site here": "github_pages",
    "herokucdn.com/error-pages/no-such-app": "heroku",
    "Sorry, this shop is currently unavailable": "shopify",
    "404 Web Site not found": "azure",
    "The thing you were looking for is no longer here": "ghost",
    "Do you want to register": "wordpress_com",
}

_extract = tldextract.TLDExtract(suffix_list_urls=())

SCHEMA = pa.schema([
    ("scan_file", pa.string()),
    ("ts", pa.string()),
    ("ip", pa.string()),
    ("port", pa.int32()),
    ("transport", pa.string()),
    ("module", pa.string()),
    ("country", pa.string()),
    ("org", pa.string()),
    ("isp", pa.string()),
    ("asn", pa.string()),
    ("cloud_provider", pa.string()),
    ("tags", pa.list_(pa.string())),
    ("product", pa.string()),
    ("version", pa.string()),
    ("os", pa.string()),
    ("cpe23", pa.list_(pa.string())),
    # attribution candidates, each already reduced to a registrable domain
    ("rdns_domains", pa.list_(pa.string())),
    ("cert_domain", pa.string()),
    ("cert_org", pa.string()),
    ("http_host_domain", pa.string()),
    ("ntlm_domain", pa.string()),
    # web
    ("http_status", pa.int32()),
    ("title", pa.string()),
    ("server_header", pa.string()),
    ("x_powered_by", pa.string()),
    ("waf", pa.string()),
    ("has_hsts", pa.bool_()),
    ("has_csp", pa.bool_()),
    ("has_xfo", pa.bool_()),
    ("has_securitytxt", pa.bool_()),
    ("last_modified", pa.timestamp("s", tz="UTC")),
    ("components", pa.list_(pa.string())),
    ("takeover", pa.string()),
    # tls
    ("has_ssl", pa.bool_()),
    ("cert_expired", pa.bool_()),
    ("cert_expires", pa.timestamp("s", tz="UTC")),
    ("cert_self_signed", pa.bool_()),
    ("tls_legacy", pa.list_(pa.string())),
    ("cert_key_bits", pa.int32()),
    ("cert_sig_alg", pa.string()),
    # vulnerabilities
    ("n_cves", pa.int32()),
    ("max_cvss", pa.float32()),
    ("max_epss", pa.float32()),
    ("kev_cves", pa.list_(pa.string())),
    ("ransomware_cves", pa.list_(pa.string())),
    ("heartbleed_vulnerable", pa.bool_()),
    # exposed-service evidence
    ("protocol_blocks", pa.list_(pa.string())),
])

PROTOCOL_BLOCKS = (
    "rdp_encryption", "ntlm", "vnc", "telnet", "mysql", "mongodb", "ftp", "kubernetes", "node_exporter",
    "microsoft_exchange", "fortinet", "mikrotik_routeros", "mikrotik_winbox", "synology_dsm", "hikvision",
    "dahua", "dahua_dvr_web", "open_dir", "snmp", "elastic", "redis", "docker", "smb", "rsync", "ssh",
)


@lru_cache(maxsize=1_000_000)
def registrable(host):
    if not host:
        return None
    host = host.strip().lower().lstrip("*.").rstrip(".")
    return _extract(host).top_domain_under_public_suffix or None


def parse_ts(value, fmt=None):
    try:
        if fmt:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        dt = parsedate_to_datetime(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError, IndexError):
        return None


def to_row(r, scan_file):
    loc = r.get("location") or {}
    http = r.get("http") or {}
    headers = http.get("headers") or {}
    ssl = r.get("ssl") or {}
    cert = ssl.get("cert") or {}
    subject = cert.get("subject") or {}
    vulns = r.get("vulns") or {}
    if not isinstance(vulns, dict):
        vulns = {}
    tags = r.get("tags") or []
    ntlm = r.get("ntlm") or {}

    html = http.get("html") or ""
    takeover = next((name for marker, name in TAKEOVER_MARKERS.items() if marker in html), None)

    cvss = [v.get("cvss") for v in vulns.values() if isinstance(v.get("cvss"), (int, float))]
    epss = [v.get("epss") for v in vulns.values() if isinstance(v.get("epss"), (int, float))]
    pubkey = cert.get("pubkey") or {}
    port = r.get("port")

    return {
        "scan_file": scan_file,
        "ts": r.get("timestamp"),
        "ip": r.get("ip_str") or r.get("ipv6"),
        "port": port if isinstance(port, int) else None,
        "transport": r.get("transport"),
        "module": (r.get("_shodan") or {}).get("module"),
        "country": loc.get("country_code"),
        "org": r.get("org"),
        "isp": r.get("isp"),
        "asn": r.get("asn"),
        "cloud_provider": (r.get("cloud") or {}).get("provider"),
        "tags": tags,
        "product": r.get("product"),
        "version": str(r["version"]) if r.get("version") is not None else None,
        "os": r.get("os"),
        "cpe23": r.get("cpe23") or [],
        "rdns_domains": [d.lower() for d in r.get("domains") or []],
        "cert_domain": registrable(subject.get("CN")),
        "cert_org": subject.get("O"),
        "http_host_domain": registrable(http.get("host")),
        "ntlm_domain": registrable(ntlm.get("dns_domain_name") or ntlm.get("fqdn")),
        "http_status": http.get("status") if isinstance(http.get("status"), int) else None,
        "title": (http.get("title") or "")[:200] or None,
        "server_header": (headers.get("server") or http.get("server") or "")[:120] or None,
        "x_powered_by": (headers.get("x-powered-by") or "")[:120] or None,
        "waf": http.get("waf"),
        "has_hsts": "strict-transport-security" in headers if http else None,
        "has_csp": "content-security-policy" in headers if http else None,
        "has_xfo": "x-frame-options" in headers if http else None,
        "has_securitytxt": bool(http.get("securitytxt")) if http else None,
        "last_modified": parse_ts(headers.get("last-modified")) if headers.get("last-modified") else None,
        "components": list((http.get("components") or {}).keys()),
        "takeover": takeover,
        "has_ssl": bool(ssl),
        "cert_expired": cert.get("expired") if ssl else None,
        "cert_expires": parse_ts(cert.get("expires"), "%Y%m%d%H%M%SZ") if cert.get("expires") else None,
        "cert_self_signed": "self-signed" in tags if ssl else None,
        "tls_legacy": [v for v in ssl.get("versions") or [] if v in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")],
        "cert_key_bits": pubkey.get("bits") if isinstance(pubkey.get("bits"), int) else None,
        "cert_sig_alg": cert.get("sig_alg"),
        "n_cves": len(vulns),
        "max_cvss": max(cvss) if cvss else None,
        "max_epss": max(epss) if epss else None,
        "kev_cves": [c for c, v in vulns.items() if v.get("kev")],
        "ransomware_cves": [c for c, v in vulns.items() if v.get("ransomware_campaign") == "Known"],
        "heartbleed_vulnerable": "VULNERABLE" in ((r.get("opts") or {}).get("heartbleed") or "") or None,
        "protocol_blocks": [b for b in PROTOCOL_BLOCKS if b in r],
    }


def gate_decision(scan_file):
    """The File Gate's verdict on this file (scripts/file_gate.py), or None if it was never gated."""
    result = DATA_DIR / "gate" / f"{scan_file.split('.')[0]}.json"
    return orjson.loads(result.read_bytes())["decision"] if result.exists() else None


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
    scan_file = DATASET_PATH.name
    decision = gate_decision(scan_file)
    if decision in (None, "BLOCK") and not os.environ.get("SKIP_FILE_GATE"):
        sys.exit(f"{scan_file}: File Gate decision is {decision or 'missing'}; run scripts/file_gate.py check first "
                 "(set SKIP_FILE_GATE=1 to override for experiments)")
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    writer = pq.ParquetWriter(OUT_PATH, SCHEMA, compression="zstd")
    buffer, n, bad, t0 = [], 0, 0, time.time()

    def flush():
        writer.write_table(pa.Table.from_pylist(buffer, schema=SCHEMA))
        buffer.clear()

    with open(DATASET_PATH, "rb") as f:
        reader = zstandard.ZstdDecompressor(max_window_size=2**31).stream_reader(f)
        for line in io.BufferedReader(reader, buffer_size=1 << 20):
            if limit and n >= limit:
                break
            try:
                buffer.append(to_row(orjson.loads(line), scan_file))
            except (orjson.JSONDecodeError, TypeError, AttributeError, ValueError):
                bad += 1
                continue
            n += 1
            if len(buffer) >= FLUSH_EVERY:
                flush()
                print(f"{n:,} banners, {n / (time.time() - t0):,.0f}/s, {bad} bad", flush=True)
    if buffer:
        flush()
    writer.close()
    print(f"done: {n:,} banners ({bad} unparseable) in {time.time() - t0:,.0f}s -> {OUT_PATH}")


if __name__ == "__main__":
    main()
