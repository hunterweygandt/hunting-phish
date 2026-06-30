"""
urls.py
"""

import re
import ipaddress
from urllib.parse import urlparse

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


def analyze_urls(msg):
    body = get_body_text(msg)
    found = URL_RE.findall(body)

    seen = set()
    results = []
    for url in found:
        url = url.rstrip(".,);")
        if url in seen:
            continue
        seen.add(url)
        results.append(
            {
                "url": url,
                "defanged": defang(url),
                "domain": registered_domain(url),
                "ip": ip_of(url),
            }
        )
    return results