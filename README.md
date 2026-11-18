# 🛡️ Vuln Radar

**A free, self-updating vulnerability intelligence hub that runs entirely on GitHub.**
It collects the latest vulnerabilities from around the world, publishes a live dashboard,
sends real-time alerts for critical and actively exploited issues, and puts out a weekly newsletter.

No server, database or paid service is needed. GitHub Actions does the work and GitHub Pages hosts the site.

| | |
|---|---|
| 🌐 **Live dashboard** | Search and filter by severity, source, time range, exploited status, CVSS or EPSS |
| 🚨 **Real-time alerts** | New CVSS ≥ 9.0 or CISA-KEV (actively exploited) vulnerabilities → GitHub Issues, Discord, Slack, Teams, Telegram, ntfy push or email |
| 📬 **Weekly newsletter** | Every Monday: published as a GitHub Release (watchers get it by email), archived on the site, and optionally emailed |
| 📡 **RSS feeds** | `feed.xml` (critical, high and exploited), `critical.xml`, `kev.xml`, `all.xml` |
| 🧩 **Open data** | `data/vulns.json` on the site, refreshed every 3 hours |

## Data sources

| Source | What it adds |
|---|---|
| [NIST NVD](https://nvd.nist.gov/) (CVE API 2.0) | Every newly published CVE, with CVSS scores, CWE and affected products |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnerabilities **confirmed exploited in the wild**, ransomware use, remediation deadlines |
| [GitHub Advisory Database](https://github.com/advisories) | Open-source package vulnerabilities (npm, PyPI, Maven, Go, RubyGems, NuGet, Rust…) |
| [FIRST EPSS](https://www.first.org/epss/) | The probability that a CVE will be exploited in the next 30 days |

Records from different sources are merged by CVE ID (GHSA aliases included).

## How it works

```
 every 3 h  ┌──────────────────────── GitHub Actions ─────────────────────────┐
 ─────────► │ fetch NVD + KEV + GHSA + EPSS → merge → alert on new critical   │
            │ (Mondays) write newsletter → commit + GitHub Release + email    │
            │ build static site → deploy to GitHub Pages                      │
            │ save state → `data` branch (single commit, keeps the repo small)│
            └─────────────────────────────────────────────────────────────────┘
```

* `vulnradar/` is the Python 3 code. It uses only the standard library, so nothing needs installing.
* `site/` is the static dashboard (HTML, CSS and vanilla JS).
* `newsletters/` is the archive of weekly issues (Markdown and HTML).
* `.github/workflows/update.yml` holds the schedule.

## Setup (5 minutes)

1. **Enable GitHub Pages:** go to *Settings → Pages → Build and deployment → Source* and choose **GitHub Actions**.
2. **Run it once:** go to *Actions → Update vulnerabilities → Run workflow*. The site will be at
   `https://<your-user>.github.io/<repo>/`.
   The first run only records what already exists, so you don't get hundreds of alerts at once. Alerts start from the second run.
3. (Recommended) **Get a free NVD API key** at <https://nvd.nist.gov/developers/request-an-api-key>
   and add it as the secret `NVD_API_KEY`. Fetching gets about 6× faster and more reliable.
4. (Optional) Turn on the notification channels you want (see below).

## Notifications

Add these under *Settings → Secrets and variables → Actions*. Each channel turns on automatically once its secret is set.

| Channel | Secrets / variables |
|---|---|
| GitHub Issues (**on by default**) | Variable `CREATE_ISSUES` = `true`/`false`. Anyone who watches the repo (*Custom → Issues*) gets notified |
| Discord | `DISCORD_WEBHOOK_URL` |
| Slack | `SLACK_WEBHOOK_URL` (Incoming Webhook) |
| Microsoft Teams | `TEAMS_WEBHOOK_URL` (Workflows webhook) |
| Telegram | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` |
| Phone push via [ntfy](https://ntfy.sh) | Variable `NTFY_TOPIC` (pick a hard-to-guess name and subscribe to it in the ntfy app) |
| Email alerts | `SMTP_HOST`, `SMTP_PORT` (465 or 587), `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `ALERT_RECIPIENTS` (comma-separated) |
| Email newsletter | The same SMTP secrets plus `NEWSLETTER_RECIPIENTS` (comma-separated, sent as BCC) |

> Gmail tip: use `smtp.gmail.com`, port `465`, and an [App Password](https://myaccount.google.com/apppasswords).

### Tuning (Actions *Variables*)

| Variable | Default | Meaning |
|---|---|---|
| `MIN_CVSS` | `9.0` | Minimum CVSS score that triggers an alert. KEV entries always alert |
| `RETENTION_DAYS` | `30` | How many days of history the dashboard keeps |
| `NVD_DAYS` | `14` | Days of NVD publications re-fetched each run, so late CVSS scores get picked up |

## Subscribe as a reader

* **Newsletter:** click **Watch → Custom → ✅ Releases** on this repo.
* **Critical alerts:** click **Watch → Custom → ✅ Issues**.
* **RSS:** add `https://<user>.github.io/<repo>/feed.xml` to your reader.

## Run locally

```bash
python -m vulnradar update --dry-run   # fetch, no notifications sent
python -m vulnradar newsletter --dry-run
python -m vulnradar build              # → _site/
python -m http.server -d _site 8000
python -m unittest discover tests
```

## License

MIT. Vulnerability data belongs to its respective sources (NVD and CISA data are public domain; the GitHub Advisory Database is CC-BY 4.0).
*This product uses the NVD API but is not endorsed or certified by the NVD.*
