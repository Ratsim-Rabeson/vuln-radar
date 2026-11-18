"""Merging, persistence and pruning of the vulnerability store."""
from __future__ import annotations

import datetime as dt
import json
import os

from .sources import SEVERITIES, iso, utcnow

# Source priority for text/score fields (earlier wins)
PRIORITY = ["NVD", "GitHub Advisory", "CISA KEV"]
LIST_FIELDS = ("aliases", "packages", "cwes", "references", "sources")


def _rank(item: dict) -> int:
    return min((PRIORITY.index(s) for s in item.get("sources", []) if s in PRIORITY), default=99)


def merge(a: dict, b: dict) -> dict:
    """Merge two records for the same vulnerability."""
    primary, secondary = (a, b) if _rank(a) <= _rank(b) else (b, a)
    out = dict(secondary)
    for k, v in primary.items():
        if v not in (None, "", [], "UNKNOWN"):
            out[k] = v
    for k in LIST_FIELDS:
        seen, merged = set(), []
        for v in (a.get(k) or []) + (b.get(k) or []):
            if v and v not in seen:
                seen.add(v)
                merged.append(v)
        out[k] = merged
    # KEV info: OR the flag, keep whichever side has details
    for k in ("kev", "ransomware"):
        out[k] = bool(a.get(k) or b.get(k))
    for k in ("kev_added", "kev_due", "kev_action"):
        out[k] = a.get(k) or b.get(k)
    # KEV titles (vendor product: name) are the most readable
    kev_side = a if "CISA KEV" in a.get("sources", []) else b if "CISA KEV" in b.get("sources", []) else None
    if kev_side and kev_side.get("title"):
        out["title"] = kev_side["title"]
    elif not out.get("title"):
        out["title"] = a.get("title") or b.get("title")
    # prefer GHSA summary over auto-generated NVD title
    ghsa_side = a if "GitHub Advisory" in a.get("sources", []) else b if "GitHub Advisory" in b.get("sources", []) else None
    if not kev_side and ghsa_side and ghsa_side.get("title"):
        out["title"] = ghsa_side["title"]
    for k in ("epss", "epss_percentile"):
        out[k] = a.get(k) if a.get(k) is not None else b.get(k)
    out["first_seen"] = min(x for x in (a.get("first_seen"), b.get("first_seen"), iso(utcnow())) if x)
    out["date"] = sort_date(out)
    return out


def sort_date(item: dict) -> str:
    """Latest of CVE publication and KEV addition (an old CVE newly exploited is news)."""
    dates = [x for x in (item.get("published"), item.get("kev_added")) if x]
    return max(dates) if dates else (item.get("first_seen") or "")


def combine(existing: dict[str, dict], new_items: list[dict]) -> tuple[dict[str, dict], list[str]]:
    """Merge new items into existing map keyed by id. Returns (store, ids_new_this_run)."""
    store = dict(existing)
    alias_to_id = {al: k for k, v in store.items() for al in v.get("aliases", [])}
    fresh = []
    now = iso(utcnow())
    for it in new_items:
        key = it["id"]
        if key not in store and key in alias_to_id:
            key = alias_to_id[key]
        # GHSA without CVE could later gain one – match through aliases too
        for al in it.get("aliases", []):
            if key not in store and al in store:
                store[key] = store.pop(al)
        if key in store:
            store[key] = merge(store[key], it)
        else:
            it = dict(it)
            it.setdefault("first_seen", now)
            it["first_seen"] = it.get("first_seen") or now
            it["date"] = sort_date(it)
            store[key] = it
            fresh.append(key)
        for al in store[key].get("aliases", []):
            alias_to_id[al] = key
    return store, fresh


def apply_kev_catalog(store: dict[str, dict], catalog: dict) -> None:
    for cid, info in catalog.items():
        if cid in store:
            it = store[cid]
            it.update({k: v for k, v in info.items() if v})
            if "CISA KEV" not in it["sources"]:
                it["sources"].append("CISA KEV")
            it["date"] = sort_date(it)


def prune(store: dict[str, dict], retention_days: int) -> dict[str, dict]:
    cutoff = iso(utcnow() - dt.timedelta(days=retention_days))
    return {k: v for k, v in store.items() if (v.get("date") or "") >= cutoff}


def sorted_items(store: dict[str, dict]) -> list[dict]:
    return sorted(store.values(), key=lambda v: (v.get("date") or "", v.get("cvss") or 0), reverse=True)


def counts(items: list[dict]) -> dict:
    c = {s: 0 for s in SEVERITIES}
    for it in items:
        c[it.get("severity", "UNKNOWN")] = c.get(it.get("severity", "UNKNOWN"), 0) + 1
    c["KEV"] = sum(1 for it in items if it.get("kev"))
    c["TOTAL"] = len(items)
    return c


def load_json(path: str, default):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return default


def save_json(path: str, obj, compact: bool = False) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        if compact:
            json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
        else:
            json.dump(obj, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)
