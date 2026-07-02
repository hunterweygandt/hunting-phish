"""
cache.py
--------
A small on-disk cache for enrichment lookups, so re-running the tool against
the same email doesn't re-burn API quota (VirusTotal free tier is ~4/min).

Different data goes stale at different rates, so each type has its own TTL:
WHOIS domain age barely moves (cache for a day); reputation verdicts change
as the world flags threats (an hour); live page scans are most perishable
(an hour here, tunable).
"""

import json
import os
import time

_CACHE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), ".cache.json"
)

# Max age in SECONDS per lookup type
TTL = {
    "whois":     24 * 60 * 60,   # domain age barely changes -> 1 day
    "vt_domain":      60 * 60,   # reputation can shift -> 1 hour
    "vt_hash":        60 * 60,
    "abuseipdb":      60 * 60,
    "urlscan":        60 * 60,   # live page scan, most perishable -> 1 hour
}
DEFAULT_TTL = 60 * 60

# global kill switch for the --no-cache flag; when False every get() misses
ENABLED = True


def _load():
    # graceful degradation: unreadable/corrupt cache is treated as empty,
    # never crashes the tool
    try:
        with open(_CACHE_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, ValueError, OSError):
        return {}


def _save(data):
    try:
        with open(_CACHE_PATH, "w") as f:
            json.dump(data, f)
    except OSError:
        pass  # if we can't write, just skip caching


def get(kind, key):
    """
    Return a cached value for (kind, key) if present AND still fresh, else
    None. An expired entry returns None
    """
    if not ENABLED:
        return None
    entry = _load().get(f"{kind}:{key}")
    if not entry:
        return None
    age = time.time() - entry.get("fetched_at", 0)
    if age >= TTL.get(kind, DEFAULT_TTL):
        return None                      # too old -> force a live fetch
    return entry.get("value")


def set(kind, key, value):
    """Store a value with the current timestamp."""
    data = _load()
    data[f"{kind}:{key}"] = {"value": value, "fetched_at": time.time()}
    _save(data)