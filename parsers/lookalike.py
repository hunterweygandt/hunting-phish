"""
lookalike.py
------------
Two sender-spoofing checks that plain header parsing misses:

1. HOMOGLYPHS - display names built from lookalike Unicode characters, e.g.
   "𝗣aym𝗲nt" using mathematical-bold letters instead of ASCII. We normalize
   the text with Unicode NFKC; if normalizing *changes* it, someone used
   fancy characters to imitate normal ones.

2. LOOKALIKE BRAND DOMAINS - sender domains that impersonate a known brand,
   e.g. "netflix-billing-update.com" or "secure-paypaI.com" (capital I posing
   as lowercase l). We fold common look-alike characters back to normal, then
   check whether a known brand name is hiding inside a domain that isn't the
   brand's real one.
"""
# Note: need to figure out a better way to incorporate this


import re
import unicodedata

# Brand core names to watch for impersonation
BRANDS = {
    "paypal", "microsoft", "apple", "amazon", "netflix", "google",
    "facebook", "instagram", "linkedin", "chase", "wellsfargo",
    "bankofamerica", "citibank", "dhl", "fedex", "ups", "usps",
    "docusign", "dropbox", "coinbase", "binance", "outlook", "office365",
    "adobe", "steam", "roblox", "venmo", "zelle",
}

# The legitimate domains for those brands - a sender ON one of these is fine.
OFFICIAL_DOMAINS = {
    "paypal.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com",
    "google.com", "facebook.com", "instagram.com", "linkedin.com", "chase.com",
    "wellsfargo.com", "bankofamerica.com", "citibank.com", "dhl.com",
    "fedex.com", "ups.com", "usps.com", "docusign.com", "dropbox.com",
    "coinbase.com", "binance.com", "outlook.com", "office365.com",
    "adobe.com", "steampowered.com", "roblox.com", "venmo.com",
}

# Common visual swaps phishers use: capital-I / one / pipe look like lowercase L,
# zero looks like O. We fold these back before checking for brand names.
_CONFUSABLES = str.maketrans({"I": "l", "1": "l", "|": "l", "0": "o"})


def has_homoglyphs(text):
    #True if the text contains lookalike Unicode characters
    if not text:
        return False
    return unicodedata.normalize("NFKC", text) != text


def _domain_from_header(from_hdr):
    # Pull the raw domain (case preserved) straight from the From header
    if not from_hdr:
        return None
    m = re.search(r"@([A-Za-z0-9.\-]+)", from_hdr)
    return m.group(1) if m else None


def lookalike_brand(from_hdr, registered_domain):
    # Return the brand a sender domain is impersonating, or None
    raw_domain = _domain_from_header(from_hdr)
    if not raw_domain:
        return None
    # a sender actually on the brand's official domain is legitimate
    if registered_domain in OFFICIAL_DOMAINS:
        return None
    # fold look-alike characters, then lowercase, then hunt for a brand name
    folded = raw_domain.translate(_CONFUSABLES).lower()
    for brand in BRANDS:
        if brand in folded:
            return brand
    return None

# Words that signal a display name is claiming to be an ORGANIZATION rather
# than a person ("PayPal Security", "Acme Billing Team")
ROLE_WORDS = {
    "security", "support", "team", "service", "services", "billing",
    "account", "accounts", "notification", "notifications", "alert",
    "alerts", "help", "desk", "helpdesk", "customer", "care", "admin",
    "administrator", "noreply", "center", "official", "verification",
    "verify", "update", "updates", "rewards", "member", "membership",
    "benefits", "payroll", "payments", "payment", "department", "office",
}

# Generic filler stripped when finding the distinctive (brand-like) word.
_FILLERS = {"the", "and", "inc", "llc", "ltd", "corp", "co", "group", "of"}
# Department / function words. These describe a team or role ("Design Team",
# "Finance Department"), NOT a company being impersonated
_DEPARTMENT_WORDS = {
    "design", "marketing", "sales", "engineering", "finance", "legal",
    "operations", "product", "products", "research", "development", "dev",
    "communications", "procurement", "logistics", "quality", "creative",
    "editorial", "content", "media", "digital", "accounting", "purchasing",
    "shipping", "compliance", "audit", "corporate", "resources", "technology",
    "information", "human", "analytics", "data",
}
_STOPWORDS = ROLE_WORDS | _FILLERS | _DEPARTMENT_WORDS


def _display_name(from_hdr):
    if not from_hdr:
        return ""
    m = re.match(r'\s*"?([^"<]*)"?\s*<', from_hdr)
    return (m.group(1).strip() if m else "")


def name_domain_mismatch(from_hdr):
    """
    True when a display name CLAIMS to be an organization but the sender's
    domain doesn't reflect that claim
    """
    name = _display_name(from_hdr)
    if not name:
        return False
    words = re.findall(r"[A-Za-z0-9]+", name.lower())
    # only treat as an org claim if a role word is present
    if not any(w in ROLE_WORDS for w in words):
        return False
    # the distinctive (likely brand/org) words: not filler, reasonably long
    distinctive = [w for w in words if w not in _STOPWORDS and len(w) >= 4]
    if not distinctive:
        return False
    raw_domain = _domain_from_header(from_hdr) or ""
    folded = raw_domain.translate(_CONFUSABLES).lower()
    # if the domain backs up ANY distinctive word, the claim checks out
    if any(tok in folded for tok in distinctive):
        return False
    return True