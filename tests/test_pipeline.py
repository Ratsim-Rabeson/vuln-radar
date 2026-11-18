"""Offline tests: parse sample payloads, merge, alert selection, rendering."""
import datetime as dt
import json
import os
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnradar import notify, render, sources, store  # noqa: E402

NOW = sources.utcnow()
D = lambda days: (NOW - dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000")  # noqa: E731

NVD = {"totalResults": 3, "vulnerabilities": [
    {"cve": {"id": "CVE-2026-1001", "published": D(1), "lastModified": D(0), "vulnStatus": "Analyzed",
             "descriptions": [{"lang": "en", "value": "Remote code execution in Acme Gateway allows unauthenticated attackers to run code. More text."}],
             "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL",
                                                                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
             "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
             "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:acme:gateway:*:*:*:*:*:*:*:*"}]}]}],
             "references": [{"url": "https://acme.example/advisory"}]}},
    {"cve": {"id": "CVE-2026-1002", "published": D(2), "vulnStatus": "Awaiting Analysis",
             "descriptions": [{"lang": "en", "value": "XSS in widget."}], "metrics": {}}},
    {"cve": {"id": "CVE-2026-1003", "published": D(2), "vulnStatus": "Rejected",
             "descriptions": [{"lang": "en", "value": "** REJECT **"}]}},
]}
KEV = {"vulnerabilities": [
    {"cveID": "CVE-2026-1001", "vendorProject": "Acme", "product": "Gateway", "vulnerabilityName": "Acme Gateway OS Command Injection",
     "dateAdded": (NOW - dt.timedelta(days=1)).strftime("%Y-%m-%d"), "shortDescription": "Acme Gateway contains an OS command injection.",
     "requiredAction": "Apply updates.", "dueDate": "2026-12-09", "knownRansomwareCampaignUse": "Known", "notes": "https://acme.example/kb ; "},
    {"cveID": "CVE-2019-0001", "vendorProject": "Old", "product": "Thing", "vulnerabilityName": "Old bug",
     "dateAdded": "2020-01-01", "shortDescription": "old", "requiredAction": "x", "dueDate": "2020-02-01"},
]}
GHSA = [{"ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": "CVE-2026-1002", "summary": "Stored XSS in widget-lib",
         "description": "Long description", "severity": "moderate", "published_at": NOW.isoformat(),
         "cvss_severities": {"cvss_v3": {"score": 6.1, "vector_string": "CVSS:3.1/AV:N"}},
         "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "widget-lib"}}],
         "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", "epss": {"percentage": 0.2, "percentile": 0.9}},
        {"ghsa_id": "GHSA-zzzz-yyyy-xxxx", "cve_id": None, "summary": "Path traversal in pyfoo", "severity": "high",
         "published_at": NOW.isoformat(), "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "pyfoo"}}],
         "html_url": "https://github.com/advisories/GHSA-zzzz-yyyy-xxxx"}]


class Pipeline(unittest.TestCase):
    def build(self):
        nvd = [x for x in (sources.parse_nvd_item(e) for e in NVD["vulnerabilities"]) if x]
        kev, catalog = sources.parse_kev(KEV, NOW - dt.timedelta(days=30))
        gh = [sources.parse_ghsa(a) for a in GHSA]
        s, fresh = store.combine({}, nvd + kev + gh)
        store.apply_kev_catalog(s, catalog)
        return store.prune(s, 30), fresh

    def test_parse_and_merge(self):
        s, fresh = self.build()
        self.assertEqual(set(s), {"CVE-2026-1001", "CVE-2026-1002", "GHSA-zzzz-yyyy-xxxx"})
        a = s["CVE-2026-1001"]
        self.assertTrue(a["kev"] and a["ransomware"])
        self.assertEqual(a["severity"], "CRITICAL")
        self.assertEqual(a["cvss"], 9.8)
        self.assertEqual(a["title"], "Acme Gateway: Acme Gateway OS Command Injection")
        self.assertIn("NVD", a["sources"]); self.assertIn("CISA KEV", a["sources"])
        self.assertEqual(a["vendor"], "acme")
        b = s["CVE-2026-1002"]
        self.assertEqual(b["severity"], "MEDIUM")           # from GHSA since NVD unscored
        self.assertEqual(b["title"], "Stored XSS in widget-lib")
        self.assertEqual(b["packages"], ["npm:widget-lib"])
        self.assertEqual(b["aliases"], ["GHSA-aaaa-bbbb-cccc"])
        self.assertEqual(b["epss"], 0.2)
        self.assertEqual(s["GHSA-zzzz-yyyy-xxxx"]["severity"], "HIGH")

    def test_remerge_is_stable(self):
        s, _ = self.build()
        s2, fresh = store.combine(s, [sources.parse_ghsa(GHSA[0])])
        self.assertEqual(fresh, [])
        self.assertEqual(len(s2), len(s))

    def test_alerts(self):
        s, _ = self.build()
        items = store.sorted_items(s)
        since = sources.iso(NOW - dt.timedelta(days=3))
        alerts = notify.select_alerts(items, set(), 9.0, since)
        self.assertEqual([a["id"] for a in alerts], ["CVE-2026-1001"])
        self.assertEqual(notify.select_alerts(items, {"CVE-2026-1001"}, 9.0, since), [])
        self.assertEqual(len(notify.select_alerts(items, set(), 7.0, since)), 1)  # GHSA high has no score

    def test_render(self):
        s, _ = self.build()
        items = store.sorted_items(s)
        with tempfile.TemporaryDirectory() as d:
            render.write_site_data(items, d, {"repo": "me/vuln-radar"})
            render.write_feeds(items, d, "https://me.github.io/vuln-radar/")
            with open(os.path.join(d, "data", "vulns.json")) as f:
                data = json.load(f)
            self.assertEqual(data["counts"]["KEV"], 1)
            for f in ("feed.xml", "kev.xml", "critical.xml", "all.xml"):
                ET.parse(os.path.join(d, f))  # well-formed
            self.assertEqual(len(ET.parse(os.path.join(d, "kev.xml")).findall(".//item")), 1)
        n = render.build_newsletter(items, NOW + dt.timedelta(minutes=1), "https://x/")
        self.assertEqual([i["id"] for i in n["kev"]], ["CVE-2026-1001"])
        md, page = render.newsletter_markdown(n), render.newsletter_html(n)
        self.assertIn("CVE-2026-1001", md)
        self.assertIn("<!doctype html>", page)


if __name__ == "__main__":
    unittest.main()
