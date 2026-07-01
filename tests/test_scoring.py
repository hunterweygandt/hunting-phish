#Automated tests for the scoring engine.
#Run them all with:  pytest

from parsers.score import score_email, verdict


def test_clean_email_scores_zero():
    # no signals fired -> score 0 -> LOOKS CLEAN
    signals = {
        "from_returnpath_mismatch": False,
        "spf_fail": False,
        "urgency": False,
    }
    total, reasons = score_email(signals)
    assert total == 0
    assert verdict(total) == "LOOKS CLEAN"


def test_urgency_alone_is_low():
    # a single weak signal should NOT reach a scary verdict
    signals = {"urgency": True}
    total, reasons = score_email(signals)
    assert total == 1
    assert verdict(total) == "LOOKS CLEAN"


def test_stacked_signals_reach_phishing():
    # several signals together should cross into LIKELY PHISHING
    signals = {
        "from_returnpath_mismatch": True,   # +2
        "dmarc_fail": True,                 # +2
        "spf_fail": True,                   # +1
        "urgency": True,                    # +1
        "new_domain": True,                 # +3
    }
    total, reasons = score_email(signals)
    assert total == 9
    assert verdict(total) == "LIKELY PHISHING"