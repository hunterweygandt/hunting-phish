"""
Tests for the enrichment cache.

This is the feature where a bug is *dangerous* - a cache that serves stale
threat intel could wave through something that's since turned malicious. So
these tests hammer the safety behavior: fresh entries are used, stale entries
are ignored (forcing a live re-fetch), the kill switch works, and a corrupt
cache file degrades gracefully instead of crashing.

Each test points the cache at a temp file so it never touches the real
.cache.json, and cleans up after itself.
"""

import time
import parsers.cache as cache


def _fresh_cache(tmp_path):
    """Point the cache module at an isolated temp file and reset its state."""
    cache._CACHE_PATH = str(tmp_path / "test_cache.json")
    cache.ENABLED = True
    return cache


def test_fresh_entry_is_returned(tmp_path):
    c = _fresh_cache(tmp_path)
    c.set("vt_domain", "example.com", {"malicious": 0})
    assert c.get("vt_domain", "example.com") == {"malicious": 0}


def test_missing_key_returns_none(tmp_path):
    c = _fresh_cache(tmp_path)
    assert c.get("vt_domain", "never-seen.com") is None


def test_expired_entry_forces_refetch(tmp_path):
    # THE CRITICAL ONE: an entry past its TTL must read as a miss, so the
    # caller goes back to the live API instead of trusting stale data.
    c = _fresh_cache(tmp_path)
    c.set("urlscan", "http://evil.test", {"malicious": True})

    # backdate the timestamp to 2 hours ago (urlscan TTL is 1 hour)
    data = c._load()
    data["urlscan:http://evil.test"]["fetched_at"] = time.time() - 7200
    c._save(data)

    assert c.get("urlscan", "http://evil.test") is None


def test_entry_just_inside_ttl_is_still_fresh(tmp_path):
    # boundary check: something fetched 30 min ago is still within the 1-hour
    # reputation TTL and should be served from cache.
    c = _fresh_cache(tmp_path)
    c.set("vt_domain", "example.com", {"malicious": 0})
    data = c._load()
    data["vt_domain:example.com"]["fetched_at"] = time.time() - 1800  # 30 min
    c._save(data)
    assert c.get("vt_domain", "example.com") == {"malicious": 0}


def test_disabled_cache_always_misses(tmp_path):
    # the --no-cache kill switch: even a fresh entry must not be returned.
    c = _fresh_cache(tmp_path)
    c.set("vt_domain", "example.com", {"malicious": 0})
    c.ENABLED = False
    try:
        assert c.get("vt_domain", "example.com") is None
    finally:
        c.ENABLED = True  # restore so other tests aren't affected


def test_corrupt_cache_file_degrades_gracefully(tmp_path):
    # a garbage cache file must not crash the tool - it should read as empty.
    c = _fresh_cache(tmp_path)
    with open(c._CACHE_PATH, "w") as f:
        f.write("{ this is not valid json ]")
    assert c.get("vt_domain", "example.com") is None  # no exception raised


def test_different_kinds_dont_collide(tmp_path):
    # same key text under different kinds must stay separate.
    c = _fresh_cache(tmp_path)
    c.set("vt_domain", "x", {"src": "domain"})
    c.set("vt_hash", "x", {"src": "hash"})
    assert c.get("vt_domain", "x") == {"src": "domain"}
    assert c.get("vt_hash", "x") == {"src": "hash"}