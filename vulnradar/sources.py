"""Fetch + normalize vulnerabilities from public sources.

Sources:
  * CISA Known Exploited Vulnerabilities (KEV) catalog
  * NIST National Vulnerability Database (NVD) CVE API 2.0
  * GitHub Advisory Database (reviewed advisories, all ecosystems)
  * FIRST EPSS (exploit prediction scores, used for enrichment)

Every item is normalized to a flat dict (see `blank_item`).
"""
from __future__ import annotations

import datetime as dt
import re
import time
import urllib.parse

from . import http

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_URL = "https://api.github.com/advisories"
EPSS_URL = "https://api.first.org/data/v1/epss"

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(d: dt.datetime) -> str:
    return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def norm_date(s: str | None) -> str | None:
    """Normalize assorted date strings to ISO-8601 UTC 'YYYY-MM-DDTHH:MM:SSZ'."""
    if not s:
        return None
    s = s.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        return s + "T00:00:00Z"
    s2 = s.replace("Z", "+00:00")
    try:
        d = dt.datetime.fromisoformat(s2)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return iso(d)


def severity_from_score(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def norm_severity(s: str | None, score: float | None = None) -> str:
    if s:
        s = s.upper()
        if s == "MODERATE":
            s = "MEDIUM"
        if s in SEVERITIES:
            return s
    return severity_from_score(score)


def first_sentence(text: str, limit: int = 140) -> str:
    text = " ".join((text or "").split())
    m = re.match(r"(.+?[.!?])(\s|$)", text)
    s = m.group(1) if m else text
    return s if len(s) <= limit else s[: limit - 1].rstrip() + "…"


def blank_item(id_: str) -> dict:
    return {
        "id": id_,               # CVE-xxxx or GHSA-xxxx
        "aliases": [],
        "title": "",
        "description": "",
        "severity": "UNKNOWN",
        "cvss": None,             # float
        "cvss_version": None,
        "vector": None,
        "epss": None,             # probability 0..1
        "epss_percentile": None,
        "published": None,
        "modified": None,
        "kev": False,
        "kev_added": None,
        "kev_due": None,
        "kev_action": None,
        "ransomware": False,
        "vendor": None,
        "product": None,
        "packages": [],           # ["npm:lodash", ...]
        "cwes": [],
        "references": [],
        "sources": [],
        "url": None,
    }


# ---------------------------------------------------------------- CISA KEV

def parse_kev(data: dict, since: dt.datetime) -> tuple[list[dict], dict]:
    """Return (recent KEV items, {cve: kev_info} for the *whole* catalog)."""
    items, catalog = [], {}
    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID")
        if not cve:
            continue
        info = {
            "kev": True,
            "kev_added": norm_date(v.get("dateAdded")),
            "kev_due": v.get("dueDate"),
            "kev_action": v.get("requiredAction"),
            "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
        }
        catalog[cve] = info
        added = info["kev_added"]
        if not added or added < iso(since):
            continue
        it = blank_item(cve)
        it.update(info)
        it["title"] = f'{v.get("vendorProject", "")} {v.get("product", "")}: {v.get("vulnerabilityName", "")}'.strip()
        it["description"] = v.get("shortDescription") or ""
        it["vendor"] = v.get("vendorProject")
        it["product"] = v.get("product")
        it["cwes"] = [c for c in (v.get("cwes") or []) if c]
        it["sources"] = ["CISA KEV"]
        it["url"] = f"https://nvd.nist.gov/vuln/detail/{cve}"
        it["references"] = [r for r in re.split(r"\s*;\s*", v.get("notes") or "") if r.startswith("http")][:4]
        items.append(it)
    return items, catalog


def fetch_kev(since: dt.datetime):
    return parse_kev(http.get_json(KEV_URL), since)


# ---------------------------------------------------------------- NVD

def _pick_metric(metrics: dict):
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                     ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        arr = metrics.get(key) or []
        if not arr:
            continue
        m = next((x for x in arr if x.get("type") == "Primary"), arr[0])
        cd = m.get("cvssData", {})
        return cd.get("baseScore"), cd.get("baseSeverity") or m.get("baseSeverity"), cd.get("vectorString"), ver
    return None, None, None, None


def _vendor_product(cve: dict):
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                parts = (match.get("criteria") or "").split(":")
                if len(parts) > 5:
                    return parts[3].replace("_", " "), parts[4].replace("_", " ")
    return None, None


def parse_nvd_item(entry: dict) -> dict | None:
    c = entry.get("cve", {})
    cid = c.get("id")
    if not cid or c.get("vulnStatus") == "Rejected":
        return None
    it = blank_item(cid)
    desc = next((d.get("value", "") for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    if desc.startswith("** REJECT"):
        return None
    it["description"] = desc
    score, sev, vector, ver = _pick_metric(c.get("metrics", {}) or {})
    it["cvss"] = float(score) if score is not None else None
    it["severity"] = norm_severity(sev, it["cvss"])
    it["vector"], it["cvss_version"] = vector, ver
    it["published"] = norm_date(c.get("published"))
    it["modified"] = norm_date(c.get("lastModified"))
    it["cwes"] = sorted({d.get("value") for w in c.get("weaknesses", []) or []
                         for d in w.get("description", []) or []
                         if (d.get("value") or "").startswith("CWE-")})
    it["references"] = [r.get("url") for r in c.get("references", []) or [] if r.get("url")][:6]
    it["vendor"], it["product"] = _vendor_product(c)
    if c.get("cisaExploitAdd"):
        it["kev"] = True
        it["kev_added"] = norm_date(c.get("cisaExploitAdd"))
        it["kev_due"] = c.get("cisaActionDue")
        it["kev_action"] = c.get("cisaRequiredAction")
    vp = " ".join(x for x in (it["vendor"], it["product"]) if x)
    it["title"] = (vp.title() + ": " if vp else "") + first_sentence(desc, 120)
    it["sources"] = ["NVD"]
    it["url"] = f"https://nvd.nist.gov/vuln/detail/{cid}"
    return it


def fetch_nvd(since: dt.datetime, until: dt.datetime, api_key: str | None = None, log=print):
    headers = {"apiKey": api_key} if api_key else {}
    pause = 1.0 if api_key else 6.5  # NVD public rate limit: 5 req / 30 s
    items, start, total = [], 0, None
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    while total is None or start < total:
        q = urllib.parse.urlencode({
            "pubStartDate": since.strftime(fmt), "pubEndDate": until.strftime(fmt),
            "resultsPerPage": 2000, "startIndex": start,
        })
        data = http.get_json(f"{NVD_URL}?{q}", headers=headers, timeout=180)
        total = data.get("totalResults", 0)
        vulns = data.get("vulnerabilities", []) or []
        for e in vulns:
            it = parse_nvd_item(e)
            if it:
                items.append(it)
        log(f"  NVD: {min(start + len(vulns), total)}/{total}")
        if not vulns:
            break
        start += len(vulns)
        if start < total:
            time.sleep(pause)
    return items


# ---------------------------------------------------------------- GitHub Advisory DB

def parse_ghsa(a: dict) -> dict:
    cve = a.get("cve_id")
    ghsa = a.get("ghsa_id")
    it = blank_item(cve or ghsa)
    if cve and ghsa:
        it["aliases"] = [ghsa]
    it["title"] = a.get("summary") or ""
    it["description"] = a.get("description") or a.get("summary") or ""
    score = None
    sevs = a.get("cvss_severities") or {}
    for k in ("cvss_v4", "cvss_v3"):
        s = (sevs.get(k) or {}).get("score")
        if s:
            score = float(s)
            it["vector"] = (sevs.get(k) or {}).get("vector_string")
            it["cvss_version"] = "4.0" if k == "cvss_v4" else "3.x"
            break
    if score is None and (a.get("cvss") or {}).get("score"):
        score = float(a["cvss"]["score"])
        it["vector"] = a["cvss"].get("vector_string")
    it["cvss"] = score
    it["severity"] = norm_severity(a.get("severity"), score)
    it["published"] = norm_date(a.get("published_at"))
    it["modified"] = norm_date(a.get("updated_at"))
    pk = []
    for v in a.get("vulnerabilities", []) or []:
        p = v.get("package") or {}
        if p.get("name"):
            pk.append(f'{p.get("ecosystem", "?")}:{p["name"]}')
    it["packages"] = sorted(set(pk))[:10]
    it["cwes"] = [c.get("cwe_id") for c in a.get("cwes", []) or [] if c.get("cwe_id")]
    it["references"] = [r for r in (a.get("references") or []) if isinstance(r, str)][:6]
    epss = a.get("epss")
    if isinstance(epss, list):
        epss = epss[0] if epss else None
    if isinstance(epss, dict) and epss.get("percentage") is not None:
        it["epss"] = float(epss["percentage"])
        it["epss_percentile"] = float(epss.get("percentile") or 0)
    it["sources"] = ["GitHub Advisory"]
    it["url"] = a.get("html_url")
    return it


def fetch_ghsa(since: dt.datetime, token: str | None = None, max_pages: int = 15, log=print):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{GHSA_URL}?type=reviewed&per_page=100&sort=published&direction=desc"
    items = []
    for page in range(max_pages):
        data, hdrs = http.get(url, headers=headers)
        stop = False
        for a in data:
            pub = norm_date(a.get("published_at"))
            if pub and pub < iso(since):
                stop = True
                break
            items.append(parse_ghsa(a))
        log(f"  GHSA: page {page + 1}, {len(items)} advisories")
        nxt = re.search(r'<([^>]+)>;\s*rel="next"', hdrs.get("Link", "") or hdrs.get("link", ""))
        if stop or not nxt:
            break
        url = nxt.group(1)
    return items


# ---------------------------------------------------------------- EPSS enrichment

def fetch_epss(cves: list[str], log=print) -> dict:
    out = {}
    cves = [c for c in cves if c.startswith("CVE-")]
    for i in range(0, len(cves), 100):
        batch = cves[i:i + 100]
        data = http.get_json(f"{EPSS_URL}?cve={','.join(batch)}")
        for row in data.get("data", []):
            try:
                out[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, ValueError):
                pass
        time.sleep(0.3)
    log(f"  EPSS: scored {len(out)} CVEs")
    return out
