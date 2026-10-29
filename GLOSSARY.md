# Sales Intelligence for Cybersecurity

Turns raw internet-scan files into a ranked list of companies a cybersecurity vendor should call, with the evidence behind each ranking.

## Scan data

**Scan File**:
One compressed file of Banners delivered by the data provider; the unit of ingestion. Hundreds to thousands arrive each month.
_Avoid_: dump, export, batch

**Banner**:
One record in a Scan File: what one Service answered when scanned, on one day.
_Avoid_: row, event, document

**Service**:
One reachable door on the internet: an IP address plus a port.
_Avoid_: host, server, endpoint

**Landlord**:
The CDN, cloud or hosting provider that owns the IP a Service runs on, as named in `org`/`isp`. Never the Company.
_Avoid_: owner, organisation (when meaning the IP holder)

**Honeypot**:
A decoy Service built to look vulnerable. Excluded before any scoring.

## Companies

**Company**:
A business identified by its Registrable Domain; the unit that is scored and shown to sellers.
_Avoid_: account, organisation, customer, org

**Registrable Domain**:
The domain a business actually registers (e.g. `acmedental.com.au`, not `portal.acmedental.com.au`), taken from the certificate subject or HTTP host before reverse-DNS domains, after removing Landlord domains.
_Avoid_: hostname, website

**Attribution**:
Linking a Banner to exactly one Company.
_Avoid_: matching, entity resolution (in user-facing text)

**Unattributed Banner**:
A Banner with no trustworthy Registrable Domain. Counted and reported, never guessed into a Company.

## Scoring

**Signal**:
A deterministic, explainable fact about a Banner that suggests its Company needs security help (e.g. a KEV CVE, exposed Remote Desktop, an expired certificate).
_Avoid_: feature, indicator, flag

**Evidence**:
The specific Banners and values behind a Signal, shown to the seller so the claim can be checked.

**Need**:
How exposed a Company is, from its Signals.

**Maturity Marker**:
Evidence that a Company already invests in security (e.g. a web application firewall). Lowers Need and tells the seller a vendor may already be present.
_Avoid_: negative signal, protection

**Fit**:
How well a Company matches the vendor's buyer profile (industry, footprint size).

**Urgency**:
Why the seller should call now rather than later (e.g. an actively exploited CVE, a certificate about to expire).
_Avoid_: timing, trigger

**Priority Score**:
The combination of Need, Fit and Urgency that orders Companies for a seller. Always computed, never produced by an LLM.
_Avoid_: lead score, rank

## Quality

**File Gate**:
The checks a Scan File must pass before its results reach sellers. Each check is either *block* or *warn*.
_Avoid_: release gate, validation step

**Golden Set**:
Hand-labelled Companies used to measure Attribution, industry classification and ranking, re-run whenever a prompt or model changes.
_Avoid_: test set, ground truth
