"""
hosting.py
"""

# Registered domains of hosting services commonly abused to host payloads, phishing pages, and redirects
ABUSED_HOSTING_DOMAINS = {
    "googleapis.com",       # storage.googleapis.com buckets
    "firebaseapp.com",      # firebase-hosted phishing pages
    "web.app",              # firebase's other domain
    "amazonaws.com",        # s3 buckets
    "cloudfront.net",       # aws cdn
    "windows.net",          # azure blob storage
    "blob.core.windows.net",
    "cloudflare.net",
    "r2.dev",               # cloudflare r2
    "pages.dev",            # cloudflare pages
    "workers.dev",          # cloudflare workers
    "github.io",            # github pages
    "glitch.me",
    "netlify.app",
    "vercel.app",
    "herokuapp.com",
    "weebly.com",
    "wixsite.com",
    "sharepoint.com",       # abused for internal-looking phishing
    "onedrive.live.com",
    "storage.googleapis.com",
}


def is_abused_host(domain):
    """True if the registered domain is a known-abused hosting service."""
    if not domain:
        return False
    return domain.lower() in ABUSED_HOSTING_DOMAINS