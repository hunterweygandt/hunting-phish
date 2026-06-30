"""
score.py
--------
The verdict layer. Everything else in this project *collects* signals;
this is the part that *decides* what they add up to.
"""

# How many points each signal is worth when it fires. Higher = stronger evidence of phishing.
WEIGHTS = {
    # --- header / auth signals ---
    "from_returnpath_mismatch": 2,   # visible sender != envelope sender
    "replyto_mismatch": 1,           # replies redirect elsewhere
    "spf_fail": 1,
    "dkim_fail": 1,
    "dmarc_fail": 2,
    "urgency": 1,                    # pressure language in subject
    # --- enrichment signals ---
    "new_domain": 3,                 # domain registered very recently
    "vt_domain_flagged": 4,          # VirusTotal calls a domain bad
    "ip_abuse": 3,                   # AbuseIPDB has reports on the IP
    "urlscan_malicious": 4,          # URLScan's behavioral verdict
    # --- attachment signals ---
    "dangerous_attachment": 4,       # high-risk ext / double ext / type mismatch
    "attachment_vt_flagged": 5,      # VirusTotal calls a file bad
}

# Where the verdict lines fall
THRESHOLD_PHISHING = 6
THRESHOLD_SUSPICIOUS = 3


def score_email(signals):
    total = 0
    reasons = []
    for name, fired in signals.items():
        if fired:
            points = WEIGHTS.get(name, 0)
            total += points
            reasons.append((name, points))
    reasons.sort(key=lambda r: r[1], reverse=True)  # heaviest first
    return total, reasons


def verdict(score):
    if score >= THRESHOLD_PHISHING:
        return "LIKELY PHISHING"
    if score >= THRESHOLD_SUSPICIOUS:
        return "SUSPICIOUS"
    return "LOOKS CLEAN"