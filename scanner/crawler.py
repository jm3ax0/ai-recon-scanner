"""
crawler.py - Finds pages, links and forms on the target website.

To test for XSS / SQL injection we first need to know WHERE user input goes
into the application. Those places are called "injection points":
  * URL parameters:  /search.php?q=hello   -> parameter "q"
  * HTML forms:      <form><input name="id"></form> -> parameter "id"

The crawler starts at the base URL, follows links on the SAME website only,
and collects every injection point it sees.
"""
import logging
from collections import deque
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

import config
from scanner.http_client import HttpClient, Response

log = logging.getLogger(__name__)

SKIP_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".js",
                   ".pdf", ".zip", ".gz", ".woff", ".woff2", ".ttf", ".mp4", ".mp3")


class PageParser(HTMLParser):
    """Collects links and forms from one HTML page."""

    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("a", "iframe", "frame") and (a.get("href") or a.get("src")):
            self.links.append(a.get("href") or a.get("src"))
        elif tag == "form":
            self._form = {"action": a.get("action") or "", "method": (a.get("method") or "get").lower(),
                          "inputs": {}}
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = a.get("name")
            if name and a.get("type", "").lower() not in ("file", "image", "reset"):
                self._form["inputs"][name] = a.get("value") or ""

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _is_excluded(url: str) -> bool:
    """Never visit pages that could log us out or break the lab."""
    low = url.lower()
    return any(word in low for word in config.CRAWL_EXCLUDE_KEYWORDS)


def _strip_query(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


async def crawl(client: HttpClient, base_url: str, extra_urls: list[str] | None = None,
                max_pages: int = config.MAX_CRAWL_PAGES, include_post: bool = False):
    """
    Returns (pages, injection_points).
      pages            -> list of Response objects we downloaded
      injection_points -> list of {"method", "url", "params", "source"}
    """
    origin = urlparse(base_url).netloc
    queue = deque([base_url] + (extra_urls or []))
    seen: set[str] = set()
    pages: list[Response] = []
    points: dict[tuple, dict] = {}

    def add_point(method: str, url: str, params: dict, source: str):
        if not params or _is_excluded(url) or any(_is_excluded(k) for k in params):
            return
        key = (method, _strip_query(url), tuple(sorted(params)))
        points.setdefault(key, {"method": method, "url": _strip_query(url),
                                "params": params, "source": source})

    while queue and len(pages) < max_pages:
        url = queue.popleft()
        if url in seen or _is_excluded(url) or url.lower().endswith(SKIP_EXTENSIONS):
            continue
        seen.add(url)

        resp = await client.get(url)
        if not resp:
            continue
        pages.append(resp)

        # Query string on the URL itself = injection point
        query = dict(parse_qsl(urlparse(resp.url).query, keep_blank_values=True))
        add_point("GET", resp.url, query, "url")

        if "html" not in resp.headers.get("Content-Type", "html").lower():
            continue
        parser = PageParser()
        try:
            parser.feed(resp.text)
        except Exception as exc:  # broken HTML should never crash the scan
            log.debug("HTML parse error on %s: %s", url, exc)

        for form in parser.forms:
            action = urljoin(resp.url, form["action"]) if form["action"] else resp.url
            if urlparse(action).netloc != origin:
                continue
            if form["method"] == "get":
                add_point("GET", action, form["inputs"], f"form on {_strip_query(resp.url)}")
            elif include_post:
                add_point("POST", action, form["inputs"], f"form on {_strip_query(resp.url)}")
            else:
                log.info("Skipping POST form %s (use --test-post to include)", action)

        for link in parser.links:
            absolute = urljoin(resp.url, link.split("#")[0])
            if urlparse(absolute).scheme in ("http", "https") and urlparse(absolute).netloc == origin:
                if absolute not in seen:
                    queue.append(absolute)

    log.info("Crawled %d pages, found %d injection points", len(pages), len(points))
    return pages, list(points.values())
