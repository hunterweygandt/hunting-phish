#!/usr/bin/env python3
import sys

from parsers.headers import analyze_headers, load_email
from parsers.urls import analyze_urls
from parsers.attachments import analyze_attachments
from parsers.score import score_email, verdict
from parsers.enrich import (
    NEW_DOMAIN_DAYS,
    is_new_domain,
    whois_age_days,
    virustotal_domain,
    virustotal_hash,
    vt_domain_link,
    vt_file_link,
    VT_API_KEY,
    abuseipdb_check,
    abuseipdb_link,
    ABUSEIPDB_API_KEY,
    urlscan_lookup,
    URLSCAN_API_KEY,
)


def hr(char="-", width=60):
    return char * width


def print_report(header_info, url_info, attachment_info):
    print(hr("="))
    print(" Hunting Phish")
    print(hr("="))

    # --- sender / auth section -------------------------------------
    print("\n[ SENDER ]")
    print(f"  From:        {header_info['from']}")
    print(f"  Return-Path: {header_info['return_path']}")
    print(f"  Reply-To:    {header_info['reply_to']}")
    print(f"  Subject:     {header_info['subject']}")
    print(f"  Date:        {header_info['date']}")

    print("\n[ AUTHENTICATION ]")
    for mech, status in header_info["auth"].items():
        status = status or "not present"
        print(f"  {mech.upper():6} {status}")

    # --- urls section ----------------------------------------------
    print(f"\n[ URLS FOUND ]  ({len(url_info)})")
    if not url_info:
        print("  (none)")
    for u in url_info:
        print(f"  {u['defanged']}")
        print(f"      domain: {u['domain']}")

    # --- flags / verdict -------------------------------------------
    print("\n[ FLAGS ]")
    if header_info["flags"]:
        for flag in header_info["flags"]:
            print(f"  (!) {flag}")
    else:
        print("  none raised by header checks")

    # --- enrichment ---------------------------------------
    print("\n[ ENRICHMENT ]")
    # start collecting scoring signals: header signals + enrichment + attachments
    signals = dict(header_info["signals"])
    signals.update({
        "new_domain": False,
        "vt_domain_flagged": False,
        "ip_abuse": False,
        "urlscan_malicious": False,
        "dangerous_attachment": False,
        "attachment_vt_flagged": False,
    })
    if not VT_API_KEY:
        print("  (note: virustotal key not set - skipping VirusTotal lookups)")
    if not ABUSEIPDB_API_KEY:
        print("  (note: abuseipdb key not set - skipping IP reputation lookups)")
    if not URLSCAN_API_KEY:
        print("  (note: urlscan key not set - skipping URL scans)")
    checked = set()
    for u in url_info:
        url = u["url"]
        domain = u["domain"]
        ip = u["ip"]

        # header line for this URL
        print(f"  {u['defanged']}")

        us = urlscan_lookup(url)
        if us is not None:
            v = us["verdict"]
            if v and v["malicious"]:
                print(f"      (!) URLSCAN flagged malicious (score {v['score']})")
                signals["urlscan_malicious"] = True
            if us["result_link"]:
                print(f"      urlscan: {us['result_link']}")

        # --- host-level checks ---
        host = domain or ip
        if host and host not in checked:
            checked.add(host)

            if domain:
                age = whois_age_days(domain)
                if age is None:
                    print(f"      domain age: unknown")
                else:
                    print(f"      domain age: {age} days")
                    if is_new_domain(age):
                        print(f"      (!) NEW DOMAIN - registered within "
                              f"{NEW_DOMAIN_DAYS} days")
                        signals["new_domain"] = True

                vt = virustotal_domain(domain)
                if vt is not None:
                    print(f"      VirusTotal: {vt['malicious']} malicious, "
                          f"{vt['suspicious']} suspicious "
                          f"({vt['harmless']} harmless)")
                    if vt["malicious"] > 0 or vt["suspicious"] > 0:
                        print(f"      (!) FLAGGED BY VIRUSTOTAL")
                        signals["vt_domain_flagged"] = True
                    print(f"      report: {vt_domain_link(domain)}")

            elif ip:
                print(f"      host is a raw IP: {ip}")
                rep = abuseipdb_check(ip)
                if rep is not None:
                    loc = rep["country"] or "?"
                    isp = rep["isp"] or "?"
                    print(f"      AbuseIPDB: score {rep['abuse_score']}/100, "
                          f"{rep['total_reports']} reports  ({loc}, {isp})")
                    if rep["abuse_score"] > 0:
                        print(f"      (!) IP REPORTED FOR ABUSE")
                        signals["ip_abuse"] = True
                print(f"      report: {abuseipdb_link(ip)}")

    if not url_info:
        print("  (no URLs to enrich)")


    # --- attachments -----------------------------------------------
    print(f"\n[ ATTACHMENTS ]  ({len(attachment_info)})")
    if not attachment_info:
        print("  (none)")
    for a in attachment_info:
        print(f"  {a['filename']}  ({a['size']} bytes)")
        print(f"      sha256: {a['sha256']}")
        print(f"      claimed ext: {a['extension'] or '(none)'}   "
              f"actual type: {a['detected_type'] or 'unknown'}")

        if a["high_risk"]:
            print(f"      (!) HIGH-RISK extension")
        if a["macro_office"]:
            print(f"      (!) macro-capable Office file")
        if a["double_extension"]:
            print(f"      (!) DOUBLE EXTENSION (disguised payload)")
        if a["type_mismatch"]:
            print(f"      (!) TYPE MISMATCH - claims {a['extension']} "
                  f"but is actually executable")
        if a["high_risk"] or a["double_extension"] or a["type_mismatch"]:
            signals["dangerous_attachment"] = True

        vth = virustotal_hash(a["sha256"])
        if vth is not None:
            print(f"      VirusTotal: {vth['malicious']} malicious, "
                  f"{vth['suspicious']} suspicious")
            if vth["malicious"] > 0 or vth["suspicious"] > 0:
                signals["attachment_vt_flagged"] = True
                print(f"      (!) FLAGGED BY VIRUSTOTAL")
        print(f"      report: {vt_file_link(a['sha256'])}")

    # --- verdict ---------------------------------------------------
    total, reasons = score_email(signals)
    print(f"\n[ VERDICT ]  {verdict(total)}  (risk score {total})")
    if reasons:
        for name, points in reasons:
            print(f"  +{points}  {name}")
    else:
        print("  no risk signals fired")

    print("\n" + hr("="))


def main():
    if len(sys.argv) != 2:
        print("usage: python analyzer.py <path-to-.eml>")
        sys.exit(1)

    path = sys.argv[1]
    msg = load_email(path)

    header_info = analyze_headers(msg)
    url_info = analyze_urls(msg)
    attachment_info = analyze_attachments(msg)

    print_report(header_info, url_info, attachment_info)


if __name__ == "__main__":
    main()
