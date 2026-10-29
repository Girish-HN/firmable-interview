# A Company is a Registrable Domain; unattributable Banners are counted, not guessed

Each Banner names up to three candidate owners: the IP holder (`org`), reverse-DNS `domains`, and the TLS certificate / HTTP host. In this data `org` is usually a Landlord (Incapsula on 32% of Banners, Google on 22%), and reverse-DNS domains are often the hosting provider's, so we identify a Company by the Registrable Domain taken from the certificate subject or HTTP host first, then reverse-DNS domains with Landlord domains removed. Banners with no trustworthy domain (often the riskiest, e.g. exposed Remote Desktop on an ISP IP) are kept as Unattributed and their share is reported, rather than guessed into a Company.

## Considered Options

- **`org` as the Company**: rejected, because it ranks CDNs and clouds as the top leads.
- **Fuzzy/LLM matching of every Banner to a company name**: rejected for the baseline because its errors would be invisible and non-reproducible. The LLM is reserved for the ambiguous tail and measured against the Golden Set (see ADR-0002).

## Consequences

- Recall is lower than it could be: some real exposures never reach a seller. The Unattributed share is a headline metric.
- Changing the key later means re-attributing every historical Banner, so this is deliberately decided up front.
