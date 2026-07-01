#End-to-end tests: run whole sample emails through the full pipeline and check the verdict

from email import policy
import email

from parsers.headers import analyze_headers
from parsers.urls import analyze_urls
from parsers.attachments import analyze_attachments
from parsers.score import assemble_signals, score_email, verdict

def analyze_file(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    header_info = analyze_headers(msg)
    url_info = analyze_urls(msg)
    attachment_info = analyze_attachments(msg)
    # use the SAME assembly the real tool uses (no enrichment = no API calls)
    signals = assemble_signals(header_info, url_info, attachment_info)
    total, _ = score_email(signals)
    return total, verdict(total)


def test_clean_sample_is_clean():
    total, v = analyze_file("samples/01_clean.eml")
    assert v == "LOOKS CLEAN"


def test_classic_phish_is_flagged():
    total, v = analyze_file("samples/02_classic_phish.eml")
    assert v == "LIKELY PHISHING"


def test_malicious_attachment_is_flagged():
    total, v = analyze_file("samples/03_malicious_attachment.eml")
    assert v == "LIKELY PHISHING"
    assert total >= 6


def test_subtle_lookalike_is_flagged():
    total, v = analyze_file("samples/04_subtle_lookalike.eml")
    assert v == "SUSPICIOUS"


def test_ip_based_link_is_flagged():
    total, v = analyze_file("samples/05_ip_based_link.eml")
    assert v == "SUSPICIOUS"


def test_trusted_host_with_other_signals_flags():
    # payload on googleapis + auth fail + urgency
    total, v = analyze_file("samples/06_trusted_host_phish.eml")
    assert v == "LIKELY PHISHING"


def test_trusted_host_alone_stays_clean():
    # legit link on googleapis, nothing else wrong
    total, v = analyze_file("samples/07_trusted_host_legit.eml")
    assert v == "LOOKS CLEAN"


def test_offlist_impersonation_is_caught():
    # "Contoso" is NOT in the brand list - caught by name/domain mismatch,
    # proving detection generalizes beyond the hardcoded brands
    total, v = analyze_file("samples/08_offlist_impersonation.eml")
    assert v in ("SUSPICIOUS", "LIKELY PHISHING")


def test_nested_redirect_is_flagged():
    total, v = analyze_file("samples/09_nested_redirect.eml")
    assert v == "LIKELY PHISHING"