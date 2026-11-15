"""
http_client.py - A small, polite, asynchronous HTTP client.

Every web request in the project goes through this class, so the safety
limits are enforced in ONE place:
  * a Semaphore limits how many requests run at the same time
  * a RateLimiter limits how many requests are sent per second
  * every request has a timeout
  * errors are logged and turned into `None` instead of crashing the scan
"""
import asyncio
import logging
import time
from dataclasses import dataclass, field

import aiohttp

import config

log = logging.getLogger(__name__)


@dataclass
class Response:
    """The parts of an HTTP response we care about."""
    url: str
    status: int
    headers: dict
    text: str
    set_cookies: list = field(default_factory=list)
    elapsed: float = 0.0


class RateLimiter:
    """Allows at most `rate` calls per second (spreads them out evenly)."""

    def __init__(self, rate: float):
        self.interval = 1.0 / rate
        self._next_time = 0.0
        self._lock = asyncio.Lock()

    async def wait(self):
        async with self._lock:
            now = time.monotonic()
            if self._next_time > now:
                await asyncio.sleep(self._next_time - now)
                now = self._next_time
            self._next_time = now + self.interval


class HttpClient:
    """Use as: `async with HttpClient(cookie=...) as client: await client.get(url)`."""

    def __init__(self, cookie: str | None = None,
                 rate: float = config.HTTP_RATE_LIMIT,
                 concurrency: int = config.MAX_CONCURRENT_HTTP):
        self.cookie = cookie
        self.sem = asyncio.Semaphore(concurrency)
        self.limiter = RateLimiter(rate)
        self.request_count = 0
        self.session: aiohttp.ClientSession | None = None

    async def __aenter__(self):
        headers = {"User-Agent": config.USER_AGENT}
        if self.cookie:
            headers["Cookie"] = self.cookie  # e.g. DVWA login session
        self.session = aiohttp.ClientSession(
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=config.HTTP_TIMEOUT),
            # ssl=False: practice labs usually use self-signed certificates
            connector=aiohttp.TCPConnector(ssl=False),
            # unsafe=True lets aiohttp keep cookies for IP addresses like 127.0.0.1
            cookie_jar=aiohttp.CookieJar(unsafe=True),
        )
        return self

    async def __aexit__(self, *exc):
        await self.session.close()

    async def request(self, method: str, url: str, params: dict | None = None,
                      data: dict | None = None, allow_redirects: bool = True) -> Response | None:
        """Send one request. Returns a Response, or None if something went wrong."""
        async with self.sem:
            await self.limiter.wait()
            self.request_count += 1
            start = time.monotonic()
            try:
                async with self.session.request(method, url, params=params, data=data,
                                                allow_redirects=allow_redirects) as resp:
                    body = await resp.content.read(config.MAX_RESPONSE_BYTES)
                    text = body.decode(resp.charset or "utf-8", errors="replace")
                    return Response(
                        url=str(resp.url),
                        status=resp.status,
                        headers={k: v for k, v in resp.headers.items()},
                        text=text,
                        set_cookies=resp.headers.getall("Set-Cookie", []),
                        elapsed=time.monotonic() - start,
                    )
            except (aiohttp.ClientError, TimeoutError, UnicodeError, ValueError) as exc:
                log.debug("Request failed %s %s: %s", method, url, exc)
                return None

    async def get(self, url: str, params: dict | None = None,
                  allow_redirects: bool = True) -> Response | None:
        return await self.request("GET", url, params=params, allow_redirects=allow_redirects)
