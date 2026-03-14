"""
hash_lookup.py
──────────────
SHA-256 reputation lookup against:
  1. MalwareBazaar  (free, no key required)
  2. VirusTotal     (optional — set VT_API_KEY env var in Streamlit secrets)
"""

import hashlib
import os
import requests
from dataclasses import dataclass, field
from typing import Optional


def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class ThreatIntel:
    sha256: str
    found: bool = False
    malicious: bool = False
    sources: list = field(default_factory=list)

    mb_tags: list       = field(default_factory=list)
    mb_signature: str   = ""
    mb_first_seen: str  = ""
    mb_reporter: str    = ""
    mb_file_type: str   = ""
    mb_url: str         = ""

    vt_malicious: int   = 0
    vt_total: int       = 0
    vt_url: str         = ""

    error: str          = ""


def lookup_malwarebazaar(sha256: str, timeout: int = 10) -> ThreatIntel:
    intel = ThreatIntel(sha256=sha256)
    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        query_status = data.get("query_status", "")

        if query_status == "hash_not_found":
            intel.found    = False
            intel.malicious = False
            return intel

        if query_status == "ok":
            info = data.get("data", [{}])[0]
            intel.found        = True
            intel.malicious    = True
            intel.sources.append("MalwareBazaar")
            intel.mb_tags      = info.get("tags") or []
            intel.mb_signature = info.get("signature") or ""
            intel.mb_first_seen= info.get("first_seen") or ""
            intel.mb_reporter  = info.get("reporter") or ""
            intel.mb_file_type = info.get("file_type") or ""
            intel.mb_url       = f"https://bazaar.abuse.ch/sample/{sha256}/"
            return intel

        intel.error = f"MalwareBazaar: unexpected status '{query_status}'"
        return intel

    except requests.exceptions.Timeout:
        intel.error = "MalwareBazaar: request timed out"
        return intel
    except Exception as e:
        intel.error = f"MalwareBazaar: {e}"
        return intel


def lookup_virustotal(sha256: str, api_key: str, timeout: int = 10) -> Optional[ThreatIntel]:
    if not api_key:
        return None

    intel = ThreatIntel(sha256=sha256)
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=timeout,
        )
        if resp.status_code == 404:
            intel.found = False
            return intel

        resp.raise_for_status()
        data  = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        intel.found        = True
        intel.vt_malicious = stats.get("malicious", 0)
        intel.vt_total     = sum(stats.values())
        intel.vt_url       = f"https://www.virustotal.com/gui/file/{sha256}"
        intel.malicious    = intel.vt_malicious > 0
        if intel.malicious:
            intel.sources.append("VirusTotal")
        return intel

    except Exception as e:
        intel.error = f"VirusTotal: {e}"
        return intel


def lookup_hash(sha256: str) -> ThreatIntel:
    """Query MalwareBazaar (always) and VirusTotal (if VT_API_KEY is set)."""
    vt_key = os.environ.get("VT_API_KEY", "")
    mb = lookup_malwarebazaar(sha256)

    if vt_key:
        vt = lookup_virustotal(sha256, vt_key)
        if vt:
            if vt.found:
                mb.found = True
            if vt.malicious:
                mb.malicious = True
            if "VirusTotal" in vt.sources and "VirusTotal" not in mb.sources:
                mb.sources.append("VirusTotal")
            mb.vt_malicious = vt.vt_malicious
            mb.vt_total     = vt.vt_total
            mb.vt_url       = vt.vt_url

    return mb


def lookup_file(path: str) -> tuple:
    sha256 = sha256_of_file(path)
    return sha256, lookup_hash(sha256)