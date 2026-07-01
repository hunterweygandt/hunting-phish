"""
score.py
--------
The verdict layer. Everything else in this project *collects* signals;
this is the part that *decides* what they add up to.

The WEIGHTS and the THRESHOLDS below are the analyst judgment
"""

from parsers.hosting import is_abused_host

# How many points each signal is worth when it fires. Higher = stronger
# evidence of phishing.
WEIGHTS = {
    # --- header / auth signals ---
    "from_returnpath_mismatch": 2,   # visible sender != envelope sender
    "replyto_mismatch": 1,           # replies redirect elsewhere
    "spf_fail": 1,
    "dkim_fail": 1,
    "dmarc_fail": 2,
    "urgency": 1,                    # pressure language in subject
    "homoglyph_sender": 3,           # lookalike Unicode in sender name
    "lookalike_domain": 3,           # sender domain impersonates a brand
    "sender_name_mismatch": 2,       # display name org not reflected in domain
    # --- enrichment signals ---
    "new_domain": 3,                 # domain registered very recently
    "vt_domain_flagged": 4,          # VirusTotal calls a domain bad
    "ip_abuse": 3,                   # AbuseIPDB has reports on the IP
    "urlscan_malicious": 4,          # URLScan's behavioral verdict
    # --- attachment signals ---
    "dangerous_attachment": 4,       # high-risk ext / double ext / type mismatch
    "attachment_vt_flagged": 5,      # VirusTotal calls a file bad
    # --- hosting signal ---
    "trusted_host_abuse": 3,         # payload on abused legit hosting + another sign
}

# Where the verdict lines fall
THRESHOLD_PHISHING = 6
THRESHOLD_SUSPICIOUS = 3


def assemble_signals(header_info, url_info, attachment_info, enrichment=None):
    #Combine every signal into ONE dict for scoring - the single place this
    #happens, so analyzer.py and the test suite score identically and can
    #never drift apart
    enrichment = enrichment or {}
    signals = dict(header_info["signals"])
    signals.update({
        "new_domain": enrichment.get("new_domain", False),
        "vt_domain_flagged": enrichment.get("vt_domain_flagged", False),
        "ip_abuse": enrichment.get("ip_abuse", False),
        "urlscan_malicious": enrichment.get("urlscan_malicious", False),
        "attachment_vt_flagged": enrichment.get("attachment_vt_flagged", False),
    })

    # local: any dangerous attachment (high-risk ext / double ext / mismatch)
    signals["dangerous_attachment"] = any(
        a["high_risk"] or a["double_extension"] or a["type_mismatch"]
        for a in attachment_info
    )

    # local: trusted-host abuse. The observation (a link on abused hosting) is
    # only SCORED when the email is already showing another sign - the same
    # "balanced" rule, now living in one place.
    on_trusted_host = any(is_abused_host(u["domain"]) for u in url_info)
    other_signals_fired = any(signals.values())
    signals["trusted_host_abuse"] = on_trusted_host and other_signals_fired

    return signals


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
    """Turn a numeric score into a human-readable call."""
    if score >= THRESHOLD_PHISHING:
        return "LIKELY PHISHING"
    if score >= THRESHOLD_SUSPICIOUS:
        return "SUSPICIOUS"
    return "LOOKS CLEAN"