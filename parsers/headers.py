"""
headers.py
----------
pull the sender info and the authentication results out of a raw .eml file.
"""

import email
import re
from email import policy

from parsers.tld import extract as _tld


def load_email(path):
    with open(path, "rb") as f:
        # policy.default gives us modern, sane header handling
        return email.message_from_binary_file(f, policy=policy.default)


def domain_of(address):
    if not address:
        return None
    # grab whatever is after the last @ (handles 'Name <a@b.com>' too)
    match = re.search(r"@([A-Za-z0-9.\-]+)", address)
    host = match.group(1) if match else address
    ext = _tld(host)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}".lower()


def parse_auth_results(raw):
    results = {"spf": None, "dkim": None, "dmarc": None}
    if not raw:
        return results
    for mech in results:
        m = re.search(rf"\b{mech}=(\w+)", raw, re.IGNORECASE)
        if m:
            results[mech] = m.group(1).lower()
    return results


def analyze_headers(msg):
    from_hdr = msg["From"]
    return_path = msg["Return-Path"]
    reply_to = msg["Reply-To"]

    from_domain = domain_of(from_hdr)
    return_domain = domain_of(return_path)
    reply_domain = domain_of(reply_to)

    auth = parse_auth_results(msg["Authentication-Results"])

    flags = []
    # structured true/false versions of the same findings, for scoring.
    signals = {
        "from_returnpath_mismatch": False,
        "replyto_mismatch": False,
        "spf_fail": False,
        "dkim_fail": False,
        "dmarc_fail": False,
        "urgency": False,
    }

    # the visible From domain doesn't match the envelope sender
    if from_domain and return_domain and from_domain != return_domain:
        signals["from_returnpath_mismatch"] = True
        flags.append(
            f"From domain ({from_domain}) != Return-Path domain ({return_domain})"
        )

    # Reply-To pointing somewhere else
    if reply_domain and from_domain and reply_domain != from_domain:
        signals["replyto_mismatch"] = True
        flags.append(
            f"Reply-To domain ({reply_domain}) != From domain ({from_domain})"
        )

    # any auth mechanism that explicitly failed
    for mech, verdict in auth.items():
        if verdict in ("fail", "softfail", "none"):
            signals[f"{mech}_fail"] = True   # spf_fail / dkim_fail / dmarc_fail
            flags.append(f"{mech.upper()} = {verdict}")

    # flag pressure/urgency language in the subject line
    urgency_words = [
        "urgent",
        "immediately",
        "action required",
        "respond now",
        "final notice",
        "last chance",
        "deadline",
        "today only",
        "within 24 hours",
        "time-sensitive",
        "expires soon",
        "expiring today",
        "suspended",
        "locked",
        "disabled",
        "compromised",
        "unauthorized access",
        "security alert",
        "confirm your account",
        "unusual activity",
        "login attempt",
        "account on hold",
        "password expires",
        "payment failed",
        "refund pending",
        "billing issue",
        "transaction declined",
        "failure to respond",
        "account will be closed",
        "service will be terminated",
        "legal action",
        "penalty",
        "suspension notice",
        "access revoked",
        "non-compliance",
        "immediate attention required",
        "claim now",
        "limited time",
        "exclusive offer",
        "you've been selected",
        "gift card pending",
        "prize expires",
        "confirm to receive",
        "blocked your account",
        ]
    subject = (msg["Subject"] or "").lower()
    for word in urgency_words:
        if re.search(rf"\b{re.escape(word)}\b", subject):
            signals["urgency"] = True
            flags.append(f"Urgency language in subject: '{word}'")

    return {
        "from": from_hdr,
        "from_domain": from_domain,
        "return_path": return_path,
        "return_domain": return_domain,
        "reply_to": reply_to,
        "subject": msg["Subject"],
        "date": msg["Date"],
        "auth": auth,
        "flags": flags,
        "signals": signals,
    }