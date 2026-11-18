"""Vuln Radar CLI.

  python -m vulnradar update       # fetch sources, merge, send alerts
  python -m vulnradar newsletter   # write this week's newsletter (+ email it)
  python -m vulnradar build        # build the static site into _site/
  python -m vulnradar all [--newsletter]
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import shutil
import sys

from . import notify, render, sources, store
from .notify import env

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
STORE = os.path.join(DATA, "vulns.json")
STATE = os.path.join(DATA, "state.json")
NL_DIR = os.path.join(ROOT, "newsletters")
SITE_SRC = os.path.join(ROOT, "site")
SITE_OUT = os.path.join(ROOT, "_site")


def log(*a):
    print(*a, flush=True)


def site_url() -> str:
    url = env("SITE_URL")
    if not url and env("GITHUB_REPOSITORY"):
        owner, repo = env("GITHUB_REPOSITORY").split("/", 1)
        url = f"https://{owner.lower()}.github.io/{repo}/"
    return (url or "http://localhost:8000/").rstrip("/") + "/"


def load_store() -> dict[str, dict]:
    raw = store.load_json(STORE, {"items": []})
    return {i["id"]: i for i in raw.get("items", [])}


def save_store(s: dict[str, dict]) -> None:
    store.save_json(STORE, {"updated": sources.iso(sources.utcnow()), "items": store.sorted_items(s)}, compact=True)


def cmd_update(args) -> int:
    retention = int(env("RETENTION_DAYS", "30"))
    nvd_days = min(int(env("NVD_DAYS", "14")), 119)
    now = sources.utcnow()
    existing = load_store()
    state = store.load_json(STATE, {})
    fetched, catalog, ok = [], {}, []

    log(f"Fetching sources (retention {retention}d, NVD window {nvd_days}d)…")
    try:
        kev_items, catalog = sources.fetch_kev(now - dt.timedelta(days=retention))
        fetched += kev_items
        ok.append("CISA KEV")
        log(f"  KEV: {len(kev_items)} recent / {len(catalog)} in catalog")
    except Exception as e:
        log(f"  ! KEV failed: {e}")
    try:
        fetched += sources.fetch_nvd(now - dt.timedelta(days=nvd_days), now, env("NVD_API_KEY"), log)
        ok.append("NVD")
    except Exception as e:
        log(f"  ! NVD failed: {e}")
    try:
        fetched += sources.fetch_ghsa(now - dt.timedelta(days=min(retention, 14)), env("GITHUB_TOKEN"), log=log)
        ok.append("GitHub Advisory")
    except Exception as e:
        log(f"  ! GHSA failed: {e}")

    merged, fresh = store.combine(existing, fetched)
    store.apply_kev_catalog(merged, catalog)
    merged = store.prune(merged, retention)

    # EPSS enrichment for CVEs lacking a score (refresh all every run is too heavy)
    try:
        need = [k for k, v in merged.items() if k.startswith("CVE-") and v.get("epss") is None][:4000]
        for cve, (p, pct) in sources.fetch_epss(need, log).items():
            merged[cve]["epss"], merged[cve]["epss_percentile"] = p, pct
    except Exception as e:
        log(f"  ! EPSS failed: {e}")

    log(f"Store: {len(merged)} items ({len(fresh)} new this run). Sources OK: {', '.join(ok) or 'none'}")

    # ---- notifications
    notified = set(state.get("notified", []))
    items = store.sorted_items(merged)
    if not state.get("initialized"):
        log("First run: recording current items without sending alerts (avoids a flood).")
        notified = {i["id"] for i in items}
        state["initialized"] = sources.iso(now)
    else:
        since = sources.iso(now - dt.timedelta(days=int(env("ALERT_LOOKBACK_DAYS", "3"))))
        alerts = notify.select_alerts(items, notified, float(env("MIN_CVSS", "9.0")), since)
        log(f"Alerts: {len(alerts)} new critical/exploited")
        if not args.dry_run:
            notify.dispatch(alerts, site_url(), int(env("MAX_ALERTS", "25")), log)
        notified |= {i["id"] for i in alerts}
    state["notified"] = sorted(notified & set(merged))
    state["last_run"] = sources.iso(now)
    state["sources_ok"] = ok

    save_store(merged)
    store.save_json(STATE, state)
    return 0 if ok else 1


def cmd_newsletter(args) -> int:
    items = store.sorted_items(load_store())
    end = sources.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    n = render.build_newsletter(items, end, site_url())
    os.makedirs(NL_DIR, exist_ok=True)
    md, page = render.newsletter_markdown(n), render.newsletter_html(n)
    base = os.path.join(NL_DIR, n["id"])
    with open(base + ".md", "w", encoding="utf-8") as f:
        f.write(md)
    with open(base + ".html", "w", encoding="utf-8") as f:
        f.write(page)
    store.save_json(base + ".json", {k: n[k] for k in ("id", "start", "end", "counts")})
    log(f"Newsletter {n['id']}: {n['counts']['TOTAL']} vulns, {len(n['kev'])} new KEV")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write(f"id={n['id']}\nmd=newsletters/{n['id']}.md\n")
    rcpt = notify.recipients("NEWSLETTER_RECIPIENTS")
    if rcpt and env("SMTP_HOST") and not args.dry_run:
        try:
            notify.send_email(f"🛡️ Vuln Radar Weekly — {n['id']}", page, md, rcpt)
            log(f"  ✓ emailed {len(rcpt)} subscriber(s)")
        except Exception as e:
            log(f"  ✗ newsletter email failed: {e}")
    return 0


def cmd_build(args) -> int:
    if os.path.exists(SITE_OUT):
        shutil.rmtree(SITE_OUT)
    shutil.copytree(SITE_SRC, SITE_OUT)
    items = store.sorted_items(load_store())
    state = store.load_json(STATE, {})
    url = site_url()
    render.write_site_data(items, SITE_OUT, {"last_run": state.get("last_run"),
                                             "sources_ok": state.get("sources_ok", []),
                                             "repo": env("GITHUB_REPOSITORY")})
    render.write_feeds(items, SITE_OUT, url)
    os.makedirs(os.path.join(SITE_OUT, "newsletters"), exist_ok=True)
    for f in glob.glob(os.path.join(NL_DIR, "*.html")) + glob.glob(os.path.join(NL_DIR, "*.md")):
        shutil.copy(f, os.path.join(SITE_OUT, "newsletters"))
    with open(os.path.join(SITE_OUT, "newsletters", "index.json"), "w", encoding="utf-8") as f:
        json.dump(render.newsletter_index(NL_DIR), f)
    open(os.path.join(SITE_OUT, ".nojekyll"), "w").close()
    log(f"Site built in {SITE_OUT} ({len(items)} items) for {url}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="vulnradar")
    p.add_argument("command", choices=["update", "newsletter", "build", "all"])
    p.add_argument("--newsletter", action="store_true", help="with 'all': also write the newsletter")
    p.add_argument("--dry-run", action="store_true", help="don't send notifications/emails")
    args = p.parse_args(argv)
    if args.command == "update":
        return cmd_update(args)
    if args.command == "newsletter":
        return cmd_newsletter(args)
    if args.command == "build":
        return cmd_build(args)
    rc = cmd_update(args)
    if args.newsletter:
        cmd_newsletter(args)
    cmd_build(args)
    return rc


if __name__ == "__main__":
    sys.exit(main())
