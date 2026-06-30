"""
attachments.py
"""

import hashlib
import os

# Extensions that are executable/scriptable
HIGH_RISK_EXTENSIONS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse",
    ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".hta", ".jar", ".msi",
    ".lnk", ".iso", ".img", ".reg", ".cpl", ".dll",
}

# Office formats that can carry macros
MACRO_OFFICE_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}

# Extensions a phisher disguises payloads as
LURE_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "txt", "jpg", "jpeg", "png", "zip",
}

# Map a file's leading bytes (magic number) to what it actually is
SIGNATURES = [
    (b"MZ", "Windows executable (PE)"),
    (b"\x7fELF", "Linux executable (ELF)"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP / Office (zip-based)"),
    (b"\xd0\xcf\x11\xe0", "Legacy Office (OLE)"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"\x89PNG", "PNG image"),
    (b"GIF8", "GIF image"),
    (b"Rar!", "RAR archive"),
]


def extract_attachments(msg):
    for part in msg.walk():
        # skip the multipart container parts themselves
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        # treat anything with a filename or marked 'attachment' as an attachment
        if filename is None and disposition != "attachment":
            continue
        payload = part.get_payload(decode=True)  # handles base64 for us
        if payload is None:
            continue
        yield (filename or "(unnamed)", payload)


def sha256_of(data):
    return hashlib.sha256(data).hexdigest()


def detect_type(data):
    for sig, name in SIGNATURES:
        if data.startswith(sig):
            return name
    return None


def has_double_extension(filename):
    parts = filename.lower().split(".")
    if len(parts) < 3:
        return False
    return parts[-2] in LURE_EXTENSIONS


def extension_mismatch(extension, detected):
    if not detected:
        return False
    ext = extension.lstrip(".").lower()
    return "executable" in detected.lower() and ext in LURE_EXTENSIONS


def analyze_attachments(msg):
    results = []
    for filename, data in extract_attachments(msg):
        ext = os.path.splitext(filename)[1].lower()
        detected = detect_type(data)
        results.append(
            {
                "filename": filename,
                "size": len(data),
                "sha256": sha256_of(data),
                "extension": ext,
                "detected_type": detected,
                "high_risk": ext in HIGH_RISK_EXTENSIONS,
                "macro_office": ext in MACRO_OFFICE_EXTENSIONS,
                "double_extension": has_double_extension(filename),
                "type_mismatch": extension_mismatch(ext, detected),
            }
        )
    return results