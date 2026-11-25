"""HTTP helper.

This host's TLS 1.3 handshakes to some external APIs are dropped mid-flight
(SSLEOFError). Falling back to TLS 1.2 per host fixes it, and remembering the
choice stops every later call from paying for the failed handshake again.
"""

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

_TLS12_ONLY: set[str] = set()
_SECRET_HEADERS = {"authorization", "apikey", "x-api-key", "x-goog-api-key", "cookie"}


class _Redirect(urllib.request.HTTPRedirectHandler):
    """urllib forwards every header on a redirect; keys stay with the host they are for."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        was, now = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if new and (now.scheme, now.netloc) != (was.scheme, was.netloc):
            for k in [h for h in new.headers if h.lower() in _SECRET_HEADERS]:
                del new.headers[k]
        return new


def _open(req, timeout: int, ctx: ssl.SSLContext):
    handlers = [urllib.request.HTTPSHandler(context=ctx), _Redirect()]
    if urllib.parse.urlsplit(req.full_url).hostname in ("127.0.0.1", "localhost", "::1"):
        handlers.append(urllib.request.ProxyHandler({}))  # a system proxy cannot reach this host
    opener = urllib.request.build_opener(*handlers)
    return opener.open(req, timeout=timeout)


def _context(host: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if host in _TLS12_ONLY:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class NotFound(Exception):
    """The server says there is no such thing."""


def get_bytes(url: str, timeout: int = 30, attempts: int = 3, limit: int = 5_000_000) -> bytes:
    try:
        return _request(url, None, None, timeout, attempts, lambda resp: resp.read(limit + 1)[:limit])
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 410):
            raise NotFound(url) from None
        raise


def request_json(url: str, data: bytes | None = None, headers: dict | None = None,
                 timeout: int = 60, attempts: int = 3):
    return _request(url, data, headers, timeout, attempts, lambda resp: json.loads(resp.read()))


def _request(url, data, headers, timeout, attempts, read):
    host = urllib.parse.urlsplit(url).hostname or ""
    last: Exception | None = None
    for i in range(attempts):
        ctx = _context(host)
        try:
            req = urllib.request.Request(url, data=data, headers=headers or {})
            with _open(req, timeout, ctx) as resp:
                return read(resp)
        except ssl.SSLError as exc:
            _TLS12_ONLY.add(host)   # retry immediately; no backoff needed
            last = exc
        except urllib.error.HTTPError as exc:
            if exc.code not in (403, 429, 500, 502, 503, 504):
                raise  # asking again will not change the answer
            last = exc
            if i + 1 < attempts:
                after = exc.headers.get("Retry-After", "") if exc.headers else ""
                time.sleep(min(int(after), 60) if after.isdigit() else 6 * (i + 1))
        except urllib.error.URLError as exc:
            # urllib wraps TLS failures in URLError; the raw SSLError is in .reason
            if isinstance(getattr(exc, "reason", None), ssl.SSLError):
                _TLS12_ONLY.add(host)
            last = exc
            time.sleep(1 + i)
    raise last  # type: ignore[misc]


def post_json(url: str, payload: dict, headers: dict | None = None, **kw):
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    return request_json(url, data=json.dumps(payload).encode(), headers=hdrs, **kw)
