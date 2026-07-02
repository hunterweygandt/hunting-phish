"""
make_samples.py - regenerate the synthetic test emails the suite runs against.

Run once:  python make_samples.py

Every email here is FABRICATED - invented senders, example.com recipients,
and a harmless "MZ"+junk stand-in for an executable. 

Regenerates an equivalent (not byte-identical) set
"""
from email.message import EmailMessage
import os

OUT = "samples"
os.makedirs(OUT, exist_ok=True)


def save(msg, name):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(bytes(msg))
    print("wrote", name)


def build(frm, return_path, subject, auth, body,
          reply_to=None, attachments=None):
    """Assemble one .eml from just its distinguishing parts."""
    m = EmailMessage()
    m["From"] = frm
    m["Return-Path"] = return_path
    m["To"] = "<recipient@example.com>"
    m["Subject"] = subject
    m["Date"] = "Mon, 29 Jun 2026 09:00:00 -0600"
    m["Authentication-Results"] = auth
    if reply_to:
        m["Reply-To"] = reply_to
    m.set_content(body)
    for data, maintype, subtype, filename in (attachments or []):
        m.add_attachment(data, maintype=maintype, subtype=subtype,
                         filename=filename)
    return m


# 01 - CLEAN: passing auth, matching domains, benign attachment -> LOOKS CLEAN
save(build(
    '"IT Help Desk" <helpdesk@acmecorp.com>', "<helpdesk@acmecorp.com>",
    "Your account password was updated today",
    "mx.acmecorp.com; spf=pass; dkim=pass; dmarc=pass",
    "Routine notice. Your account is fine, no action needed. If your screen "
    "is unlocked keep working. Portal gives unlimited resets. "
    "Visit https://portal.acmecorp.com/help",
    attachments=[(b"Meeting notes. Nothing exciting.", "text", "plain", "notes.txt")],
), "01_clean.eml")

# 02 - CLASSIC PHISH: spoofed PayPal (capital-I lookalike), all auth fail, urgency
save(build(
    '"PayPal Security" <service@secure-paypaI.com>', "<bounce@mailer-track9.ru>",
    "Your account has been suspended - action required immediately",
    "mx.example.com; spf=fail; dkim=fail; dmarc=fail",
    "Unusual activity. Verify now or your account will be suspended:\n"
    "https://secure-paypaI.com.account-verify-helpdesk.com/login",
    reply_to="<recover@account-verify-helpdesk.com>",
), "02_classic_phish.eml")

# 03 - MALICIOUS ATTACHMENT: double extension + a file lying about its type
save(build(
    '"Accounts Payable" <billing@invoices-secure.com>', "<bounce@mailer7.ru>",
    "Outstanding invoice - please review immediately",
    "mx.example.com; spf=fail; dkim=fail; dmarc=fail",
    "See attached invoice.\nhttps://invoices-secure.com.pay-now-helpdesk.com/login",
    attachments=[
        (b"MZ\x90\x00\x03fake PE payload", "application", "octet-stream", "invoice.pdf.exe"),
        (b"MZ\x90\x00\x03fake exe as pdf", "application", "pdf", "statement.pdf"),
    ],
), "03_malicious_attachment.eml")

# 04 - SUBTLE LOOKALIKE: auth passes, attacker's own netflix lookalike domain
save(build(
    '"Billing" <noreply@netflix-billing-update.com>',
    "<noreply@netflix-billing-update.com>",
    "Final notice: update your payment to avoid suspension",
    "mx.example.com; spf=pass; dkim=pass; dmarc=pass",
    "Your payment failed. Update now:\n"
    "https://netflix-billing-update.com/account/verify",
), "04_subtle_lookalike.eml")

# 05 - IP-BASED LINK: link points at a raw IP instead of a domain
save(build(
    '"Security Team" <alert@mail-secure-login.com>',
    "<alert@mail-secure-login.com>",
    "Suspicious login attempt detected",
    "mx.example.com; spf=softfail; dkim=none; dmarc=fail",
    "We blocked a login. Confirm it was you:\nhttp://203.0.113.44/reset.php",
), "05_ip_based_link.eml")

# 06 - TRUSTED-HOST PHISH: payload on googleapis + auth fail + urgency.
#      trusted_host_abuse SHOULD count (it stacks with other signals).
save(build(
    '"Account Team" <alert@verify-notice.me>', "<bounce@mailer9.ru>",
    "We've blocked your account! Take action immediately",
    "mx.example.com; spf=fail; dkim=fail; dmarc=fail",
    "Verify now: https://storage.googleapis.com/oliiiseur/ozeutizeptzir.html#abc123",
), "06_trusted_host_phish.eml")

# 07 - TRUSTED-HOST LEGIT: a real "Design Team" email with a Google Storage
#      link and NO other red flags. Nothing should fire -> LOOKS CLEAN. This
#      is the false-positive guard: department names must not read as brands.
save(build(
    '"Design Team" <team@acmecorp.com>', "<team@acmecorp.com>",
    "Here are the mockups from our meeting",
    "mx.acmecorp.com; spf=pass; dkim=pass; dmarc=pass",
    "The files are here: https://storage.googleapis.com/acme-design/mockups.pdf",
), "07_trusted_host_legit.eml")

# 08 - OFF-LIST IMPERSONATION: "Contoso" is NOT in the brand list; caught by
#      the name/domain mismatch check -> proves detection generalizes.
save(build(
    '"Contoso Payroll Team" <hr-notice@secure-docs-portal.com>',
    "<bounce@secure-docs-portal.com>",
    "Action required: confirm your direct deposit details",
    "mx.example.com; spf=pass; dkim=pass; dmarc=pass",
    "Please confirm your payroll info: https://secure-docs-portal.com/confirm",
), "08_offlist_impersonation.eml")

# 09 - NESTED REDIRECT: the real payload (googleapis) is URL-encoded inside a
#      continueUrl= parameter on a firebaseapp link. Extraction surfaces it,
#      then trusted-host abuse fires -> LIKELY PHISHING.
save(build(
    '"Account Notification" <noreply@x-05qv3fh2.firebaseapp.com>',
    "<noreply@x-05qv3fh2.firebaseapp.com>",
    "Sign in to confirm your account - action required",
    "mx.example.com; spf=pass; dkim=pass; dmarc=fail",
    "Confirm here: https://x-05qv3fh2.firebaseapp.com/__/auth/action"
    "?apiKey=AIzaSyABC&mode=signIn"
    "&continueUrl=https%3A%2F%2Fstorage.googleapis.com%2Foliiiseur%2Fpage.html",
), "09_nested_redirect.eml")

print("\nall 9 samples written to", OUT + "/")