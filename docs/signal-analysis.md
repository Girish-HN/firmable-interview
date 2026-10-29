# Signal analysis

Evidence for which Signals go into the Priority Score. Reproduce with:

```
python scripts/extract_banners.py    # 17.6 GB Scan File -> 386 MB slim Banner table (~37 min, 1 core)
python scripts/analyze_signals.py    # attribution + Signal prevalence + lift (~2 min)
```

Input: one Scan File, 14,608,407 Banners scanned on 2026-10-26. Terms are defined in [GLOSSARY.md](../GLOSSARY.md).

## 1. Cleaning before counting

| Step | Removed / flagged | Why |
|---|---|---|
| Honeypots | 250,439 Banners | Decoys built to look vulnerable |
| Tarpits | 1,235 IPs (≥100 open ports) | Devices that answer on every port to waste scanners' time; not a real footprint |
| Landlords: many IPs | 3,312 domains on ≥50 IPs | Clouds, CDNs and ISPs, e.g. `googleusercontent.com`, `amazonaws.com`, `imperva.com`, `btcentralplus.com` |
| Landlords: multi-tenant | 1,387 domains with ≥20 Banners per IP:port | One server hosting many customer sites: website builders (`mystrikingly.com`, `my-free.website`), site platforms (`schoolloop.com`, `bandzoogle.com`) |

**Known cost:** the multi-tenant rule also catches some real firms hosting many of their own sites (e.g. `bdo.com`), and the many-IPs rule drops large enterprises. Both fall outside the likely buyer profile, but they are lost recall, recorded here deliberately.

## 2. Attribution: how many Banners reach a Company?

| Banner type | Banners | Attributed to a Company |
|---|---|---|
| All (after cleaning) | 14,032,190 | 6.2% |
| Excluding CDN edges | 8,201,457 | 8.3% |
| Web (HTTP) | 4,207,897 | 16.1% |
| Carrying a KEV CVE | 276,194 | **23.8%** |
| Exposed database | 15,454 | 16.7% |
| Exposed Remote Desktop | 46,845 | **10.4%** |

Attribution sources, in priority order: TLS certificate (2.3% of Banners), HTTP host (0.8%), Windows domain leaked by NTLM (391 Banners), reverse DNS (3.1%). Result: **362,572 Companies**.

**Finding:** the riskiest services are the hardest to attribute. Nine in ten exposed Remote Desktop servers sit on ISP or cloud IPs with nothing naming their owner. Per ADR-0001 they're counted, not guessed. In production, joining IP ranges to a firmographic database (Firmable's own core data) is the path to recovering them. That join is the single biggest lever on recall.

## 3. Prevalence and lift

**Lift** = P(Company has a KEV CVE | Signal) ÷ P(Company has a KEV CVE). Baseline: 13.45% of Companies have at least one KEV CVE.
Bigger footprints have more chances of showing *any* Signal and *any* KEV, so lift is also computed among **single-IP Companies only** (baseline 12.69%), where footprint size can't explain it.

| Signal | Kind | Companies | % | Lift | 1-IP lift |
|---|---|---|---|---|---|
| ransomware_cve | obvious | 12,956 | 3.57% | 7.4× | 7.9× |
| high_epss (≥0.5) | obvious | 56,028 | 15.45% | 6.5× | 6.9× |
| eol_software | obvious | 41,708 | 11.50% | 5.4× | 5.6× |
| **outdated_runtime** (PHP ≤7.3 / old ASP.NET in `X-Powered-By`) | hidden | 3,423 | 0.94% | 5.0× | **4.7×** |
| critical_cvss (≥9) | obvious | 38,367 | 10.58% | 4.5× | 4.6× |
| compromised | obvious | 7 | 0.00% | 4.2× | 3.9× |
| **default_page** ("Welcome to nginx!", "IIS Windows Server"…) | hidden | 19,544 | 5.39% | 2.8× | **2.4×** |
| **stale_site_3y** (`Last-Modified` > 3 years old) | hidden | 30,224 | 8.34% | 2.4× | **2.0×** |
| open_directory | obvious | 1,647 | 0.45% | 2.5× | 1.7× |
| cert_expired | obvious | 21,086 | 5.82% | 1.5× | 1.4× |
| has_security_txt | maturity | 1,227 | 0.34% | 1.5× | 1.3× |
| legacy_tls | hidden | 39,475 | 10.89% | 1.0× | 1.1× |
| cert_expiring_30d | hidden | 11,028 | 3.04% | 0.9× | 0.9× |
| has_hsts | maturity | 46,647 | 12.87% | 0.9× | 0.8× |
| takeover_candidate | hidden | 125 | 0.03% | 0.7× | 0.2× |
| self_signed | hidden | 18,690 | 5.15% | 1.0× | 0.4× |
| exposed_login_portal | hidden | 1,419 | 0.39% | 1.1× | 0.5× |
| exposed_rdp | obvious | 2,621 | 0.72% | 1.3× | 0.1× |
| exposed_database | obvious | 2,420 | 0.67% | 1.2× | 0.2× |
| exposed_remote_shell | obvious | 416 | 0.11% | 2.0× | 0.0× |
| ics_or_medical | obvious | 88 | 0.02% | 3.2× | 0.4× |
| **has_waf** | maturity | 55,358 | 15.27% | 0.3× | **0.1×** |

## 4. How to read this

1. **Three hidden Signals track real patching risk, and survive the size control:** outdated runtimes (4.7×), default pages (2.4×) and stale sites (2.0×). Default pages and stale sites carry no version number, so their lift isn't a by-product of Shodan's CVE inference. They're independent evidence of neglect, and they're visible on Companies where no CVE was inferred at all.
2. **Lift is partly circular for version-based Signals.** KEV CVEs are themselves inferred from versions (`verified: false`), so `eol_software`, `critical_cvss` and `outdated_runtime` share an input with the yardstick. They're still meaningful, but the yardstick can't independently confirm them.
3. **KEV is the wrong yardstick for exposure Signals.** Exposed Remote Desktop, databases and shells score ~0× on single-IP Companies because such services rarely reveal a version, so Shodan infers no CVE. Their risk is *access*, not *patching*. They have to be justified independently, not by lift.
4. **Urgency Signals measure timing, not risk level.** Certificates expiring within 30 days and takeover candidates don't predict KEV, as expected: they are "why now" triggers, not evidence of weak patching.
5. **A WAF is the strongest maturity marker** (0.1×): Companies behind one almost never show KEV CVEs. It should lower Need, and tells the seller a security vendor is already present.
6. **Noise:** legacy TLS, self-signed certificates and HSTS are common and ≈1×. They're dropped or given minimal weight.

## 5. Decisions: the Signal shortlist

| Role | Signals |
|---|---|
| **Need** | kev_cve (ransomware_cve weighted extra), high_epss, eol_software, outdated_runtime, default_page, stale_site_3y, open_directory, cert_expired |
| **Need: exposure** (moderate weight) | exposed_rdp, exposed_database, exposed_remote_shell, ics_or_medical |
| **Urgency** | ransomware_cve, compromised, cert_expiring_30d, takeover_candidate |
| **Maturity Marker** (lowers Need) | has_waf |
| **Dropped** | legacy_tls, self_signed, has_hsts, exposed_login_portal, has_security_txt |

**Why the exposure Signals stay despite ~0× single-IP lift:** lift against KEV can't see access risk (section 4, point 3), so they're justified externally instead.
CISA's #StopRansomware Guide says "Do not expose services, such as remote desktop protocol, on the web" and that attackers "often gain initial access to a network through exposed and poorly secured remote services" ([CISA](https://www.cisa.gov/stopransomware/ransomware-guide)).
CISA reports RDP compromise as "the second most common vector (around 13.3% of incidents)" for BlackSuit ransomware ([AA23-061A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a)).
Sophos found external remote services were "the method of initial access in 65% of IR cases in 2023" across 150+ of its own incident-response cases ([Sophos](https://www.sophos.com/en-us/press/press-releases/2024/04/cybercriminals-abuse-remote-desktop-protocol-rdp-90-attacks-handled)); that's a vendor's case mix, not a population rate.
Weight stays moderate because none of this can be validated within this dataset.

**An assumption the data disproved:** `security.txt` was expected to mark a mature security programme (lower Need). Companies publishing one have KEV CVEs 1.3× as often as average (single-IP), so it was dropped rather than kept on intuition.

## Limitations

- One snapshot: lift is correlation within a single day, not prediction of future incidents.
- No ground truth for "bought security software"; the Golden Set (hand-labelled) is the next validation step.
- Attribution covers 6.2% of Banners; every number above describes attributable Companies only.
