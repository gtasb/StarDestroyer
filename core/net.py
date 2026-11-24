"""HTTP helper.

This host's TLS 1.3 handshakes to some external APIs are dropped mid-flight
(SSLEOFError). Falling back to TLS 1.2 per host fixes it, and remembering the
choice stops every later call from paying for the failed handshake again.
"""

import json
import ssl
import time
import urllib.parse
import urllib.request

_TLS12_ONLY: set[str] = set()


def _context(host: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if host in _TLS12_ONLY:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def request_json(url: str, data: bytes | None = None, headers: dict | None = None,
                 timeout: int = 60, attempts: int = 3):
    host = urllib.parse.urlsplit(url).hostname or ""
    last: Exception | None = None
    for i in range(attempts):
        ctx = _context(host)
        try:
            req = urllib.request.Request(url, data=data, headers=headers or {})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return json.loads(resp.read())
        except ssl.SSLError as exc:
            _TLS12_ONLY.add(host)   # retry immediately; no backoff needed
            last = exc
        except Exception as exc:
            last = exc
            time.sleep(1 + i)
    raise last  # type: ignore[misc]


def post_json(url: str, payload: dict, headers: dict | None = None, **kw):
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    return request_json(url, data=json.dumps(payload).encode(), headers=hdrs, **kw)
