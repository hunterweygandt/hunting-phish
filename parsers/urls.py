"""
urls.py
"""

import re
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote

from parsers.tld import extract as _tld

URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)


def get_body_text(msg):
    chunks = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    chunks.append(part.get_content())
                except Exception:
                    # some parts have odd encodings; skip rather than crash
                    pass
    else:
        try:
            chunks.append(msg.get_content())
        except Exception:
            pass
    return "\n".join(chunks)


def defang(url):
    url = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    url = url.replace(".", "[.]")
    return url


def registered_domain(url):
    """evil-login.com out of https://account.evil-login.com/reset"""
    ext = _tld(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return None


def ip_of(url):
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    try:
        ipaddress.ip_address(host)  # raises ValueError if host isn't an IP
        return host
    except ValueError:
        return None


def nested_urls(url):
    # Pull URLs hidden inside another URL's query parameters
    out = []
    try:
        query = urlparse(url).query
    except ValueError:
        return out
    if not query:
        return out
    # parse_qs decodes each value once
    for values in parse_qs(query).values():
        for value in values:
            for candidate in (value, unquote(value)):
                for match in URL_RE.findall(candidate):
                    out.append(match.rstrip(".,);"))
    return out


def analyze_urls(msg):
    body = get_body_text(msg)
    found = URL_RE.findall(body)

    seen = set()
    results = []

    def add(url, nested=False):
        url = url.rstrip(".,);")
        if url in seen:
            return
        seen.add(url)
        results.append(
            {
                "url": url,
                "defanged": defang(url),
                "domain": registered_domain(url),
                "ip": ip_of(url),
                "nested": nested,
            }
        )

    for url in found:
        add(url, nested=False)
        # surface any URLs buried in this one's query parameters
        for inner in nested_urls(url):
            add(inner, nested=True)

    return results