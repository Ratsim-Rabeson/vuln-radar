"""Build outputs: site data JSON, RSS feeds, weekly newsletter (Markdown + HTML)."""
from __future__ import annotations

import collections
import datetime as dt
import email.utils
import html
import json
import os
import re
from xml.sax.saxutils import escape

from .sources import iso, utcnow
from .store import counts

SEV_COLOR = {"CRITICAL": "#b91c1c", "HIGH": "#c2410c", "MEDIUM": "#a16207",
             "LOW": "#15803d", "NONE": "#475569", "UNKNOWN": "#475569"}


def slim(it: dict, desc_limit: int = 700) -> dict:
    """Trim an item for the public site JSON."""
    d = {k: v for k, v in it.items() if v not in (None, "", [], False)}
    if len(d.get("description", "")) > desc_limit:
        d["description"] = d["description"][: desc_limit - 1].rstrip() + "…"
    d.pop("modified", None)
    return d


def write_site_data(items: list[dict], out_dir: str, meta: dict) -> None:
    os.makedirs(os.path.join(out_dir, "data"), exist_ok=True)
    payload = {"generated": iso(utcnow()), "counts": counts(items), **meta,
               "items": [slim(i) for i in items]}
    with open(os.path.join(out_dir, "data", "vulns.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))


def _rfc822(s: str | None) -> str:
    try:
        d = dt.datetime.fromisoformat((s or "").replace("Z", "+00:00"))
    except ValueError:
        d = utcnow()
    return email.utils.format_datetime(d)


def label(it: dict) -> str:
    bits = [it.get("severity", "UNKNOWN")]
    if it.get("cvss") is not None:
        bits[0] += f" {it['cvss']:.1f}"
    if it.get("kev"):
        bits.append("EXPLOITED (CISA KEV)")
    if it.get("ransomware"):
        bits.append("RANSOMWARE")
    return " · ".join(bits)


def rss(items: list[dict], title: str, link: str, desc: str) -> str:
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>',
           f"<title>{escape(title)}</title><link>{escape(link)}</link>",
           f"<description>{escape(desc)}</description>",
           f"<lastBuildDate>{email.utils.format_datetime(utcnow())}</lastBuildDate>"]
    for it in items:
        body = f"[{label(it)}] {it.get('description', '')}"
        out.append(
            "<item>"
            f"<title>{escape(it['id'] + ' — ' + (it.get('title') or ''))}</title>"
            f"<link>{escape(it.get('url') or link)}</link>"
            f"<guid isPermaLink=\"false\">{escape(it['id'])}</guid>"
            f"<pubDate>{_rfc822(it.get('date'))}</pubDate>"
            f"<category>{escape(it.get('severity', 'UNKNOWN'))}</category>"
            f"<description>{escape(body)}</description>"
            "</item>")
    out.append("</channel></rss>")
    return "\n".join(out)


def write_feeds(items: list[dict], out_dir: str, site_url: str) -> None:
    important = [i for i in items if i.get("kev") or i.get("severity") in ("CRITICAL", "HIGH")][:150]
    kev = [i for i in items if i.get("kev")][:150]
    crit = [i for i in items if i.get("severity") == "CRITICAL" or i.get("kev")][:150]
    feeds = {
        "feed.xml": (important, "Vuln Radar — Critical, High & Exploited"),
        "critical.xml": (crit, "Vuln Radar — Critical & Exploited only"),
        "kev.xml": (kev, "Vuln Radar — CISA Known Exploited Vulnerabilities"),
        "all.xml": (items[:300], "Vuln Radar — All new vulnerabilities"),
    }
    for name, (subset, title) in feeds.items():
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
            f.write(rss(subset, title, site_url, "Latest vulnerabilities from NVD, CISA KEV and GitHub Advisories"))


# ---------------------------------------------------------------- newsletter

def week_id(d: dt.datetime) -> str:
    y, w, _ = d.isocalendar()
    return f"{y}-W{w:02d}"


def build_newsletter(items: list[dict], end: dt.datetime, site_url: str, days: int = 7) -> dict:
    start = end - dt.timedelta(days=days)
    s_iso, e_iso = iso(start), iso(end)
    week = [i for i in items if s_iso <= (i.get("date") or "") <= e_iso]
    kev_new = sorted([i for i in week if i.get("kev") and (i.get("kev_added") or "") >= s_iso],
                     key=lambda i: i.get("kev_added") or "", reverse=True)
    critical = sorted([i for i in week if i.get("severity") == "CRITICAL" and i not in kev_new],
                      key=lambda i: ((i.get("epss") or 0), i.get("cvss") or 0), reverse=True)[:15]
    high_epss = sorted([i for i in week if (i.get("epss") or 0) >= 0.1 and i not in kev_new and i not in critical],
                       key=lambda i: i.get("epss") or 0, reverse=True)[:10]
    eco = collections.Counter(p.split(":")[0] for i in week for p in i.get("packages", []))
    vendors = collections.Counter((i.get("vendor") or "").title() for i in week if i.get("vendor"))
    return {
        "id": week_id(end - dt.timedelta(days=1)),
        "start": s_iso, "end": e_iso,
        "counts": counts(week),
        "kev": kev_new, "critical": critical, "epss": high_epss,
        "ecosystems": eco.most_common(8), "vendors": vendors.most_common(10),
        "site_url": site_url,
    }


def _md_item(i: dict) -> str:
    extra = []
    if i.get("epss") is not None:
        extra.append(f"EPSS {i['epss'] * 100:.1f}%")
    if i.get("packages"):
        extra.append(", ".join(i["packages"][:3]))
    if i.get("kev_due"):
        extra.append(f"CISA due {i['kev_due']}")
    tail = f" — _{'; '.join(extra)}_" if extra else ""
    title = (i.get("title") or "").replace("|", "/")
    return f"- **[{i['id']}]({i.get('url')})** `{label(i)}` {title}{tail}"


def newsletter_markdown(n: dict) -> str:
    c = n["counts"]
    L = [f"# 🛡️ Vuln Radar Weekly — {n['id']}",
         f"_{n['start'][:10]} → {n['end'][:10]}_ · [Live dashboard]({n['site_url']})", "",
         "## At a glance", "",
         "| Total | Critical | High | Medium | Low | Exploited (KEV) |",
         "|---:|---:|---:|---:|---:|---:|",
         f"| {c['TOTAL']} | {c['CRITICAL']} | {c['HIGH']} | {c['MEDIUM']} | {c['LOW']} | {c['KEV']} |", ""]
    L += ["## 🔥 Actively exploited — added to CISA KEV this week", ""]
    L += [_md_item(i) for i in n["kev"]] or ["_No new KEV entries this week._"]
    L += ["", "## 🚨 Top critical vulnerabilities", ""]
    L += [_md_item(i) for i in n["critical"]] or ["_None this week._"]
    if n["epss"]:
        L += ["", "## 📈 High exploit probability (EPSS ≥ 10%)", ""] + [_md_item(i) for i in n["epss"]]
    if n["vendors"]:
        L += ["", "## 🏢 Most affected vendors", "", ", ".join(f"{v} ({k})" for v, k in n["vendors"])]
    if n["ecosystems"]:
        L += ["", "## 📦 Open-source ecosystems", "", ", ".join(f"{e} ({k})" for e, k in n["ecosystems"])]
    L += ["", "---", "Sources: NIST NVD, CISA KEV, GitHub Advisory Database, FIRST EPSS. "
          "Subscribe: watch this repo → *Custom → Releases*, or use the RSS feeds on the dashboard."]
    return "\n".join(L) + "\n"


def _h_item(i: dict) -> str:
    sev = i.get("severity", "UNKNOWN")
    badge = (f'<span style="background:{SEV_COLOR.get(sev)};color:#fff;border-radius:4px;'
             f'padding:1px 6px;font-size:12px;font-weight:600">{html.escape(label(i))}</span>')
    extra = []
    if i.get("epss") is not None:
        extra.append(f"EPSS {i['epss'] * 100:.1f}%")
    if i.get("packages"):
        extra.append(", ".join(i["packages"][:3]))
    if i.get("kev_due"):
        extra.append(f"CISA due {i['kev_due']}")
    ex = f'<div style="color:#64748b;font-size:12px">{html.escape("; ".join(extra))}</div>' if extra else ""
    desc = html.escape((i.get("description") or "")[:280])
    return (f'<li style="margin:0 0 14px"><a href="{html.escape(i.get("url") or "#")}" '
            f'style="font-weight:700;color:#1d4ed8;text-decoration:none">{html.escape(i["id"])}</a> {badge}'
            f'<div style="font-weight:600;margin:2px 0">{html.escape(i.get("title") or "")}</div>'
            f'<div style="color:#334155;font-size:13px">{desc}</div>{ex}</li>')


def newsletter_html(n: dict) -> str:
    c = n["counts"]

    def section(title, rows, empty):
        body = "".join(_h_item(i) for i in rows) or f"<li><em>{empty}</em></li>"
        return f'<h2 style="font-size:18px;margin:28px 0 10px">{title}</h2><ul style="padding-left:18px">{body}</ul>'

    stats = "".join(
        f'<td style="padding:10px;text-align:center"><div style="font-size:22px;font-weight:800;color:{col}">{c[k]}</div>'
        f'<div style="font-size:11px;color:#64748b;text-transform:uppercase">{lbl}</div></td>'
        for k, lbl, col in (("TOTAL", "Total", "#0f172a"), ("CRITICAL", "Critical", SEV_COLOR["CRITICAL"]),
                            ("HIGH", "High", SEV_COLOR["HIGH"]), ("MEDIUM", "Medium", SEV_COLOR["MEDIUM"]),
                            ("KEV", "Exploited", "#7c3aed")))
    parts = [
        '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>Vuln Radar Weekly {n['id']}</title></head>",
        '<body style="margin:0;background:#f1f5f9;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0f172a">',
        '<div style="max-width:680px;margin:0 auto;background:#fff;padding:28px 24px">',
        f'<h1 style="margin:0;font-size:24px">🛡️ Vuln Radar Weekly — {n["id"]}</h1>',
        f'<p style="color:#64748b;margin:4px 0 18px">{n["start"][:10]} → {n["end"][:10]} · '
        f'<a href="{html.escape(n["site_url"])}">Open live dashboard</a></p>',
        f'<table style="width:100%;border-collapse:collapse;background:#f8fafc;border-radius:8px"><tr>{stats}</tr></table>',
        section("🔥 Actively exploited — new in CISA KEV", n["kev"], "No new KEV entries this week."),
        section("🚨 Top critical vulnerabilities", n["critical"], "None this week."),
    ]
    if n["epss"]:
        parts.append(section("📈 High exploit probability (EPSS ≥ 10%)", n["epss"], ""))
    if n["vendors"]:
        parts.append('<h2 style="font-size:18px;margin:28px 0 10px">🏢 Most affected vendors</h2><p>'
                     + html.escape(", ".join(f"{v} ({k})" for v, k in n["vendors"])) + "</p>")
    if n["ecosystems"]:
        parts.append('<h2 style="font-size:18px;margin:28px 0 10px">📦 Open-source ecosystems</h2><p>'
                     + html.escape(", ".join(f"{e} ({k})" for e, k in n["ecosystems"])) + "</p>")
    parts.append('<hr style="border:none;border-top:1px solid #e2e8f0;margin:28px 0 12px">'
                 '<p style="font-size:12px;color:#64748b">Sources: NIST NVD, CISA KEV, GitHub Advisory Database, '
                 'FIRST EPSS. You get this because you subscribed to Vuln Radar.</p></div></body></html>')
    return "".join(parts)


def newsletter_index(nl_dir: str) -> list[dict]:
    out = []
    for name in sorted(os.listdir(nl_dir) if os.path.isdir(nl_dir) else [], reverse=True):
        m = re.fullmatch(r"(\d{4}-W\d{2})\.json", name)
        if m:
            with open(os.path.join(nl_dir, name), encoding="utf-8") as f:
                meta = json.load(f)
            out.append({"id": m.group(1), "start": meta["start"], "end": meta["end"],
                        "counts": meta["counts"], "html": f"newsletters/{m.group(1)}.html",
                        "md": f"newsletters/{m.group(1)}.md"})
    return out
