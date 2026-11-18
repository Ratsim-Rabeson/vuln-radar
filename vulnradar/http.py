"""Tiny stdlib-only HTTP helpers with retries."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

USER_AGENT = "vuln-radar/1.0 (+https://github.com/topics/vulnerability-feed)"
RETRY_CODES = {403, 408, 429, 500, 502, 503, 504}


def get(url: str, headers: dict | None = None, retries: int = 4, timeout: int = 90):
    """Return (parsed_json, response_headers)."""
    h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    h.update(headers or {})
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.load(resp), dict(resp.headers)
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code not in RETRY_CODES:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last_err = e
        if attempt < retries - 1:
            time.sleep(8 * (attempt + 1))
    raise RuntimeError(f"GET {url} failed after {retries} attempts: {last_err}")


def get_json(url: str, headers: dict | None = None, **kw):
    return get(url, headers, **kw)[0]


def post_json(url: str, payload: dict, headers: dict | None = None, timeout: int = 30):
    h = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    h.update(headers or {})
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        return resp.status, body
