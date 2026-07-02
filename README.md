# Hunting Phish

A command-line phishing triage tool that takes a raw `.eml` file, runs it through
layered analysis — sender authentication, sender impersonation, URL and IP
reputation, attachment inspection — and produces a weighted risk score with a
defensible verdict.

Built from scratch in Python as a hands-on SOC/detection-engineering project. The
design goal throughout: never just *count* indicators, but *weigh* them, so that a
loud-but-harmless message and a quiet-but-dangerous one are ranked on real risk
rather than on how many boxes they tick.

```
============================================================
 Hunting Phish
============================================================
...
[ VERDICT ]  LIKELY PHISHING  (risk score 10)
  +3  trusted_host_abuse
  +3  lookalike_domain
  +2  dmarc_fail
  +1  urgency
  +1  spf_fail
============================================================
```

## What it checks

**Headers & authentication** — parses `Authentication-Results` for SPF/DKIM/DMARC
verdicts, compares the visible `From` domain against the envelope `Return-Path`
and `Reply-To`, and flags urgency/pressure language in the subject.

**Sender impersonation (three complementary layers)** — catches spoofed senders
that authentication alone misses:
- *Homoglyphs* — display names built from lookalike Unicode (e.g. mathematical-bold
  characters imitating normal letters), detected via Unicode normalization.
- *Lookalike brand domains* — a curated list of commonly-abused brands, with
  confusable-character folding so `secure-paypaI.com` (capital-I posing as `l`)
  is caught.
- *Display-name / domain mismatch* — generalizes **beyond** the brand list: if a
  display name claims to be an organization ("Contoso Payroll") that the sending
  domain doesn't support, it's flagged — for any org, not just listed ones.

**URLs** — extracts every link (plain-text and HTML), deduplicates, and defangs
them. Pulls the registered domain, detects raw-IP hosts, and **extracts URLs
hidden inside redirect parameters** (`continueUrl=`, `url=`, `redirect=`) so a
payload buried in a query string is surfaced and analyzed like any other link.

**Trusted-host abuse** — detects links hosted on legitimate services phishers
abuse *because* the domain is trusted and clean (`storage.googleapis.com`,
`*.firebaseapp.com`, S3, Azure Blob, etc.). Because plenty of real mail links to
these, it's scored only when the email is *already* showing another sign — a
balanced rule that avoids false-flagging every Google Drive link.

**Reputation enrichment** — domain and file reputation via VirusTotal, IP
reputation via AbuseIPDB, live behavioral scanning via URLScan.io, and domain
registration age via WHOIS. Each degrades gracefully if its API key is absent.
Results are cached on disk with per-type TTLs (parsers/cache.py) so repeat runs 
don't re-burn free-tier quota — a stale entry is treated as a miss, so the cache 
can only skip a redundant call, never suppress a needed one. Pass --no-cache to 
force every lookup live.

**Attachments** — extracts attachments, computes SHA256, and identifies the *real*
file type from magic bytes rather than the filename. Flags high-risk extensions,
double extensions (`invoice.pdf.exe`), and type mismatches (a `.pdf` whose bytes
say it's an executable). Only the hash is sent to VirusTotal; the file never leaves
the machine.

**Scoring** — every check emits a structured signal. A single `assemble_signals`
step combines them, a weighted model sums the ones that fired, and the tool renders
a verdict (`LOOKS CLEAN` / `SUSPICIOUS` / `LIKELY PHISHING`) that shows each
contributing signal and its weight — fully explainable, never a black box.

## How it works

```
hunting-phish/
├── analyzer.py            # entry point: runs the pipeline, prints the report
├── parsers/
│   ├── headers.py         # sender, auth, urgency, impersonation signals
│   ├── urls.py            # URL + nested-URL extraction, defanging, domain/IP
│   ├── lookalike.py       # homoglyph + brand + name/domain-mismatch detection
│   ├── hosting.py         # trusted-host abuse detection
│   ├── attachments.py     # hashing, magic-byte typing, extension checks
│   ├── enrich.py          # external API lookups (VT, AbuseIPDB, URLScan, WHOIS)
│   ├── cache.py           # TTL'd on-disk cache for API lookups
│   ├── score.py           # signal assembly + weighted verdict model
│   ├── config.py          # loads API keys from config.ini
│   └── tld.py             # shared offline public-suffix extractor
├── tests/                 # pytest suite (scoring + end-to-end sample tests)
├── make_samples.py        # regenerates the synthetic test emails
├── config.example.ini     # template (committed); copy to config.ini
├── requirements.txt       # runtime dependencies
└── requirements-dev.txt   # + pytest, for running the test suite
```

Two design principles run through it. **Single source of truth:** signal assembly
lives in one `assemble_signals` function that both the tool and the tests call, so
they can never disagree about a score; likewise config, the TLD extractor, and
URL dedup each have one home. **Graceful degradation:** any missing API key or
failed lookup returns a clean `None` and is noted, so the tool always produces a
verdict from whatever signals are available.

## Setup

Requires Python 3.10+.

```bash
git clone https://github.com/hunterweygandt/hunting-phish.git
cd hunting-phish
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt          # runtime
pip install -r requirements-dev.txt      # + test tooling (optional)
```

## Configuration

```bash
cp config.example.ini config.ini
```

Add your free-tier API keys to `config.ini` (VirusTotal, AbuseIPDB, URLScan).
`config.ini` is git-ignored and never committed; any key left blank simply disables
that lookup.

## Usage

```bash
python analyzer.py samples/example.eml
```

Run with no cache option:
```bash
python analyzer.py --no-cache samples/example.eml   # bypass the lookup cache
```


Regenerate the synthetic test emails, then run the whole set:

```bash
python make_samples.py
for f in samples/*.eml; do echo "=== $f ==="; python analyzer.py "$f"; done
```

## Testing

```bash
pytest
```

The suite covers the scoring model in isolation and whole emails end-to-end. Test
emails are synthetic (generated by `make_samples.py`) and safe to commit; real
samples belong in the git-ignored `samples/testset/` folder.

## Scoring model

Weights and thresholds live in `score.py` and are tuned by hand — analyst judgment,
not fixed truth.

| Signal | Weight |
|---|---|
| Attachment flagged by VirusTotal | 5 |
| Dangerous attachment (high-risk / double ext / type mismatch) | 4 |
| Domain flagged by VirusTotal | 4 |
| URL flagged malicious by URLScan | 4 |
| New domain (registered recently) | 3 |
| IP reported for abuse (AbuseIPDB) | 3 |
| Homoglyph sender / lookalike brand domain | 3 each |
| Trusted-host abuse (with another signal present) | 3 |
| From / Return-Path mismatch, DMARC fail | 2 each |
| Display-name / domain mismatch | 2 |
| Reply-To mismatch, SPF fail, DKIM fail, urgency | 1 each |

Verdict: **≥6** → LIKELY PHISHING, **≥3** → SUSPICIOUS, otherwise LOOKS CLEAN.

## Known limitations & roadmap

Tested against live phishing, which surfaced real gaps — some now closed, some still open:

- **Cross-script homoglyphs.** Unicode normalization catches math/fullwidth tricks
  but not Cyrillic/Greek lookalike letters (a Cyrillic `а` that looks Latin).
  Planned: confusable-script detection.
- **Auth as necessary-not-sufficient.** Passing SPF/DKIM only proves the mail came
  from the sending domain. Domain age is scored, but tighter interaction between
  "authenticated" and "freshly registered" is planned.
- **Header-parsing robustness.** Malformed/folded headers in real mail can confuse
  naive parsing. Planned: harden the parser.
- **Enrichment coverage in tests.** The test suite exercises all local signals but
  mocks out live API calls; adding response mocking for VT/AbuseIPDB/URLScan is a
  planned improvement.

## Disclaimer

For educational and authorized analysis only. Always analyze live malicious samples
in an isolated environment, never on a primary workstation.

Sample emails included in this repository are synthetic and generated for testing/demo purposes only.