"""Push notifications: Discord, Slack, Telegram, Microsoft Teams, ntfy, email, GitHub Issues.

Each channel is enabled only when its secrets/env vars are present.
"""
from __future__ import annotations

import os
import smtplib
import ssl
import urllib.parse
from email.message import EmailMessage

from . import http
from .render import label

SEV_DISCORD = {"CRITICAL": 0xB91C1C, "HIGH": 0xC2410C, "MEDIUM": 0xA16207, "LOW": 0x15803D}


def env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    return v.strip() if v and v.strip() else default


def _line(i: dict) -> str:
    return f"{i['id']} [{label(i)}] {i.get('title') or ''}"


def _safe(name, fn, log):
    try:
        fn()
        log(f"  ✓ {name}")
        return True
    except Exception as e:  # never let one channel break the run
        log(f"  ✗ {name}: {e}")
        return False


# ---------------------------------------------------------------- channels

def discord(items, site_url, more):
    url = env("DISCORD_WEBHOOK_URL")
    for start in range(0, len(items), 10):
        embeds = [{
            "title": f"{i['id']} — {(i.get('title') or '')[:200]}",
            "url": i.get("url"),
            "description": f"**{label(i)}**\n{(i.get('description') or '')[:350]}",
            "color": 0x7C3AED if i.get("kev") else SEV_DISCORD.get(i.get("severity"), 0x475569),
        } for i in items[start:start + 10]]
        content = "🛡️ **Vuln Radar alert**" if start == 0 else None
        if start + 10 >= len(items) and more:
            content = (content or "") + f"\n…and {more} more on {site_url}"
        http.post_json(url, {"content": content, "embeds": embeds, "username": "Vuln Radar"})


def slack(items, site_url, more):
    text = "🛡️ *Vuln Radar alert*\n" + "\n".join(
        f"• <{i.get('url')}|{i['id']}> *{label(i)}* {i.get('title') or ''}" for i in items)
    if more:
        text += f"\n…and {more} more: {site_url}"
    http.post_json(env("SLACK_WEBHOOK_URL"), {"text": text[:39000]})


def teams(items, site_url, more):
    text = "🛡️ **Vuln Radar alert**\n\n" + "\n\n".join(
        f"- [{i['id']}]({i.get('url')}) **{label(i)}** {i.get('title') or ''}" for i in items)
    if more:
        text += f"\n\n…and {more} more: {site_url}"
    http.post_json(env("TEAMS_WEBHOOK_URL"), {"text": text})


def telegram(items, site_url, more):
    token, chat = env("TELEGRAM_BOT_TOKEN"), env("TELEGRAM_CHAT_ID")
    lines = [f"🛡️ Vuln Radar alert ({len(items) + more} new)"] + [f"• {_line(i)}\n  {i.get('url')}" for i in items]
    if more:
        lines.append(f"…and {more} more: {site_url}")
    msg = "\n".join(lines)
    for chunk in [msg[k:k + 4000] for k in range(0, len(msg), 4000)]:
        http.post_json(f"https://api.telegram.org/bot{token}/sendMessage",
                       {"chat_id": chat, "text": chunk, "disable_web_page_preview": True})


def ntfy(items, site_url, more):
    topic = env("NTFY_TOPIC")
    server = env("NTFY_SERVER", "https://ntfy.sh")
    import urllib.request
    body = "\n".join(_line(i) for i in items[:15])
    if more or len(items) > 15:
        body += f"\n…and {more + max(0, len(items) - 15)} more"
    req = urllib.request.Request(
        f"{server.rstrip('/')}/{urllib.parse.quote(topic)}", data=body.encode(), method="POST",
        headers={"Title": f"Vuln Radar: {len(items) + more} new critical/exploited",
                 "Priority": "high", "Tags": "shield,warning", "Click": site_url})
    urllib.request.urlopen(req, timeout=30).read()


def send_email(subject: str, html_body: str, text_body: str, recipients: list[str]):
    host = env("SMTP_HOST")
    port = int(env("SMTP_PORT", "587"))
    user, pwd = env("SMTP_USER"), env("SMTP_PASSWORD")
    sender = env("SMTP_FROM", user)
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = sender            # recipients are BCC'd to keep the list private
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")
    ctx = ssl.create_default_context()
    if port == 465:
        server = smtplib.SMTP_SSL(host, port, context=ctx, timeout=60)
    else:
        server = smtplib.SMTP(host, port, timeout=60)
        server.starttls(context=ctx)
    with server:
        if user:
            server.login(user, pwd)
        # send in batches of 50 BCC
        for k in range(0, len(recipients), 50):
            server.send_message(msg, from_addr=sender, to_addrs=recipients[k:k + 50])


def recipients(var: str) -> list[str]:
    return [r.strip() for r in (env(var) or "").replace(";", ",").replace("\n", ",").split(",") if "@" in r]


def email_alert(items, site_url, more):
    rows = "".join(
        f'<li><a href="{i.get("url")}"><b>{i["id"]}</b></a> <b>{label(i)}</b><br>{i.get("title") or ""}</li>'
        for i in items)
    html_body = (f"<h2>🛡️ Vuln Radar alert</h2><ul>{rows}</ul>"
                 + (f"<p>…and {more} more.</p>" if more else "")
                 + f'<p><a href="{site_url}">Open dashboard</a></p>')
    text = "\n".join(_line(i) + "\n  " + (i.get("url") or "") for i in items)
    send_email(f"[Vuln Radar] {len(items) + more} new critical/exploited vulnerabilities",
               html_body, text, recipients("ALERT_RECIPIENTS"))


def github_issue(items, site_url, more):
    repo, token = env("GITHUB_REPOSITORY"), env("GITHUB_TOKEN")
    body = "\n".join(
        f"- [ ] **[{i['id']}]({i.get('url')})** `{label(i)}` {i.get('title') or ''}" for i in items)
    if more:
        body += f"\n\n…and {more} more on the [dashboard]({site_url})."
    kev = sum(1 for i in items if i.get("kev"))
    title = f"🚨 {len(items) + more} new critical/exploited vulnerabilities" + (f" ({kev} in CISA KEV)" if kev else "")
    http.post_json(f"https://api.github.com/repos/{repo}/issues",
                   {"title": title, "body": body, "labels": ["vuln-alert"]},
                   headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})


CHANNELS = [
    ("Discord", lambda: env("DISCORD_WEBHOOK_URL"), discord),
    ("Slack", lambda: env("SLACK_WEBHOOK_URL"), slack),
    ("Microsoft Teams", lambda: env("TEAMS_WEBHOOK_URL"), teams),
    ("Telegram", lambda: env("TELEGRAM_BOT_TOKEN") and env("TELEGRAM_CHAT_ID"), telegram),
    ("ntfy", lambda: env("NTFY_TOPIC"), ntfy),
    ("Email", lambda: env("SMTP_HOST") and recipients("ALERT_RECIPIENTS"), email_alert),
    ("GitHub Issue", lambda: (env("CREATE_ISSUES", "false").lower() == "true") and env("GITHUB_TOKEN"), github_issue),
]


def select_alerts(items: list[dict], notified: set[str], min_cvss: float, since_iso: str) -> list[dict]:
    """Items worth a push: newly exploited (KEV), or CVSS >= min_cvss, not yet notified."""
    out = []
    for i in items:
        if i["id"] in notified or (i.get("date") or "") < since_iso:
            continue
        if i.get("kev") or (i.get("cvss") or 0) >= min_cvss or (min_cvss <= 9.0 and i.get("severity") == "CRITICAL"):
            out.append(i)
    # exploited first, then by score
    return sorted(out, key=lambda i: (bool(i.get("kev")), i.get("cvss") or 0), reverse=True)


def dispatch(alerts: list[dict], site_url: str, max_items: int = 25, log=print) -> list[str]:
    if not alerts:
        log("  no new alerts")
        return []
    shown, more = alerts[:max_items], max(0, len(alerts) - max_items)
    enabled = [(n, fn) for n, cond, fn in CHANNELS if cond()]
    if not enabled:
        log("  no notification channels configured (see README → Notifications)")
    for name, fn in enabled:
        _safe(name, lambda fn=fn: fn(shown, site_url, more), log)
    return [n for n, _ in enabled]
