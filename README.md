# Hunting Phish

!!PROJECT IS IN PROGRESS!!
!!IF YOU'D LIKE TO SEE ANYTHING ADDED PLEASE REACH OUT TO ME!!

A command-line phishing triage tool that takes a raw `.eml` file, runs it through
layered analysis — sender authentication, URL and IP reputation, attachment
inspection — and produces a weighted risk score with a defensible verdict.

Build from scratch in Python as a hands-on SOC project. The
design goal throughout: never just *count* indicators, but *weigh* them, so that a
loud-but-harmless message and a quiet-but-dangerous one are ranked on real risk
rather than on how many boxes they tick.

```
============================================================
 Hunting Phish
============================================================

[ SENDER ]
  From:        "PayPal Security" <service@secure-paypaI.com>
  Return-Path: <bounce@mailer-track9.ru>
  ...
[ VERDICT ]  LIKELY PHISHING  (risk score 8)
  +2  from_returnpath_mismatch
  +2  dmarc_fail
  +1  replyto_mismatch
  +1  spf_fail
  +1  dkim_fail
  +1  urgency
============================================================
```

## What it checks

**Headers & authentication** — parses the `Authentication-Results` header for
SPF/DKIM/DMARC verdicts, compares the visible `From` domain against the envelope
`Return-Path` and `Reply-To`, and flags pressure/urgency language in the subject
using whole-word matching.

**URLs** — extracts every link from the body (plain-text and HTML parts),
deduplicates, and defangs them for safe display. Pulls the registered domain via
the public suffix list, and detects links that point at a raw IP instead of a
domain.

**Reputation enrichment** — looks each indicator up against external threat intel:
domain and file reputation via VirusTotal, IP reputation via AbuseIPDB, live
behavioral scanning via URLScan.io (which actually visits the page), and domain
registration age via WHOIS (a domain registered days ago is a strong signal).

**Attachments** — extracts attachments, computes their SHA256, and identifies the
*real* file type from magic bytes rather than trusting the filename. Flags
high-risk extensions, double extensions (`invoice.pdf.exe`), and type mismatches
(a file named `.pdf` whose bytes say it's an executable). Hashes are sent to
VirusTotal; the file itself never leaves the machine.

**Scoring** — every check emits a structured signal. A weighted model sums the
signals that fired and renders a verdict (`LOOKS CLEAN` / `SUSPICIOUS` /
`LIKELY PHISHING`), showing each contributing signal and its weight so the verdict
is fully explainable.

## How it works

The tool is organized as a small package where each module owns one
responsibility, and a single entry point composes them:

```
hunting-phish/
├── analyzer.py            # entry point: runs the pipeline, prints the report
├── parsers/
│   ├── headers.py         # sender + SPF/DKIM/DMARC + urgency analysis
│   ├── urls.py            # URL extraction, defanging, domain/IP parsing
│   ├── attachments.py     # hashing, magic-byte typing, extension checks
│   ├── enrich.py          # all external API lookups (VT, AbuseIPDB, URLScan, WHOIS)
│   ├── score.py           # the weighted verdict model
│   ├── config.py          # loads API keys from config.ini
│   └── tld.py             # shared offline public-suffix extractor
├── config.example.ini     # template (committed); copy to config.ini
└── requirements.txt
```

Two design choices worth calling out. First, every external lookup degrades
gracefully: a missing API key or a failed request returns a clean `None` and the
report notes the skip rather than crashing, so the tool always produces a verdict
from whatever signals are available. Second, secrets are never in source — keys
load from a git-ignored `config.ini`, with a blank `config.example.ini` committed
so the format is documented without exposing anything.

## Setup

Requires Python 3.10+.

```bash
git clone https://github.com/hunterweygandt/hunting-phish.git
cd hunting-phish
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Copy the example config and add your API keys:

```bash
cp config.example.ini config.ini
```

Then edit `config.ini`:

```ini
[api_keys]
virustotal = your_key_here
abuseipdb  = your_key_here
urlscan    = your_key_here
```

All three are free-tier keys. `config.ini` is git-ignored and will never be
committed. Any key left blank simply disables that lookup — the tool still runs
and scores on the remaining signals.

## Usage

```bash
python analyzer.py samples/example.eml
```

Run against the included test set to see the range of verdicts:

```bash
for f in samples/testset/*.eml; do echo "=== $f ==="; python analyzer.py "$f"; done
```

## Scoring model

Each signal carries a weight reflecting how strongly it indicates phishing. The
weights and verdict thresholds live in `score.py` and are tuned by hand — they are
the analyst judgment, not a fixed truth.

| Signal | Weight |
|---|---|
| Attachment flagged by VirusTotal | 5 |
| Dangerous attachment (high-risk / double ext / type mismatch) | 4 |
| Domain flagged by VirusTotal | 4 |
| URL flagged malicious by URLScan | 4 |
| New domain (registered recently) | 3 |
| IP reported for abuse (AbuseIPDB) | 3 |
| From / Return-Path domain mismatch | 2 |
| DMARC fail | 2 |
| Reply-To mismatch, SPF fail, DKIM fail, urgency | 1 each |

Verdict: **≥6** → LIKELY PHISHING, **≥3** → SUSPICIOUS, otherwise LOOKS CLEAN.

## Known limitations & roadmap

This tool was tested against live phishing samples, which surfaced real gaps worth
being honest about:

- **Trusted-host abuse.** Attackers increasingly host payloads on legitimate
  infrastructure (`storage.googleapis.com`, `*.firebaseapp.com`). Because the
  registered domain is Google's — old and clean — domain-age and reputation checks
  pass. Planned: detect known-abused hosting and shift scrutiny to the path/bucket.
- **Authentication is necessary, not sufficient.** A passing SPF/DKIM only proves
  the mail genuinely came from the sending domain — attackers authenticate their
  own throwaway domains correctly. Planned: weight sender-domain age and lookalike
  detection more heavily when auth passes but the domain is freshly registered.
- **Header parsing robustness.** Real-world mail contains malformed and folded
  headers that can confuse naive parsing. Planned: harden the parser against
  these edge cases.
- **Lookalike / homoglyph senders.** Unicode-spoofed display names and
  near-miss domains aren't yet scored. Planned: homoglyph normalization and
  edit-distance comparison against common brands.

## Disclaimer

For educational and authorized analysis use only. Always analyze live malicious
samples in an isolated environment, never on a primary workstation.