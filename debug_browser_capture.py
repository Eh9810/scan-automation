# -*- coding: utf-8 -*-
"""
debug_browser_capture.py
========================
כלי אבחון מקומי – מאפשר להבין מה בדיוק חוסם את GitHub Actions מלהתחבר ל-Moodle של TAU.

הרצה:
  pip install selenium requests
  python debug_browser_capture.py

מה הסקריפט עושה:
  1. פותח Chrome אמיתי (לא headless) עם CDP (Chrome DevTools Protocol) פעיל.
  2. ממתין לך להתחבר ידנית ולגלוש בכמה קורסים.
  3. במקביל מתעד ב-background:
       • כל בקשת רשת (URL, method, headers שנשלחו + headers שהתקבלו, status, body חלקי)
       • חיפוש אוטומטי אחר דפי חסימה של F5 WAF (Support ID, זמן מדויק, URL)
       • כל cookies (session + NIDP)
       • localStorage / sessionStorage
       • console logs של הדפדפן
       • כל אובייקטי JavaScript של Moodle (M.cfg, M.util, מפתח sesskey)
       • כל headers אבטחה: Content-Security-Policy, HSTS, X-Frame-Options, Server, X-F5-*
  4. בסוף (כשסוגרים את הדפדפן או לוחצים Enter) שומר הכל לתיקייה:
       waf_debug_YYYYMMDD_HHMMSS/
     עם קבצים:
       summary.txt          – סיכום בעברית + אבחון סוג החסימה
       network_log.json     – כל הבקשות
       blocked_pages.json   – דפי חסימה בלבד (F5 / Access Denied)
       cookies.json         – כל ה-cookies
       storage.json         – localStorage + sessionStorage
       moodle_config.json   – M.cfg ונתוני Moodle מ-JS
       security_headers.json– headers אבטחה לפי URL
       console_log.txt      – console.log/warn/error מהדפדפן
       page_sources/        – HTML גולמי של כל דף שנפתח

הגדרות (ניתן לשנות):
  START_URL    – כתובת ה-URL שתיפתח בהתחלה
  WAIT_MINUTES – כמה דקות להמתין לגלישה (ברירת מחדל: 15 דקות)
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse

# ── dependency check ──────────────────────────────────────────────────────────
try:
    import requests
except ImportError:
    sys.exit("Missing: pip install requests")

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
except ImportError:
    sys.exit("Missing: pip install selenium")

# ── configuration ─────────────────────────────────────────────────────────────
START_URL = "https://moodle.tau.ac.il/local/mycourses/"
WAIT_MINUTES = 15          # how long to wait for manual browsing
POLL_INTERVAL = 3          # seconds between each capture cycle
TZ_IL = timezone(timedelta(hours=3))

# ── regex patterns ────────────────────────────────────────────────────────────
_F5_UUID_RE = re.compile(
    r"Your support ID is:\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)
_MOODLE_SESSKEY_RE = re.compile(r'"sesskey"\s*:\s*"([a-zA-Z0-9]+)"')
_BLOCK_INDICATORS = {
    "f5_waf_ip_block": [
        re.compile(r"Your support ID is:", re.I),
    ],
    "access_denied": [
        re.compile(r"Access denied", re.I),
        re.compile(r"בקשה נדחתה", re.U),
    ],
    "bot_score": [
        re.compile(r"bot\s*(score|detect|challeng)", re.I),
        # "captcha" is intentionally omitted – the NIDP login page references
        # reCAPTCHA in its HTML even during a normal, successful SSO flow, so
        # matching it here causes false positives on legitimate login pages.
        re.compile(r"אתה רובוט|are you a robot", re.I),
    ],
    "rate_limit": [
        # Bare "429" is too broad – it matches course IDs, form fields, etc.
        # This pattern requires "429" to appear next to an HTTP/Error/status
        # keyword, OR next to "too many"/"rate" (e.g. "429 Too Many Requests").
        re.compile(r"(?:HTTP|Error|status)[^0-9]{0,10}429\b|429[^0-9]{0,20}(?:too.{0,10}many|rate)", re.I),
        re.compile(r"rate.?limit|too many requests", re.I),
        re.compile(r"נחסמת זמנית|temporarily blocked", re.I),
    ],
    "geo_asn": [
        re.compile(r"geo.?(block|restrict)|country.?block|asn.?block", re.I),
    ],
    # NOTE: "maintenance" is NOT listed here; it is handled separately inside
    # detect_block_type() using a title-based check to prevent false positives
    # from "maintenance" appearing in Moodle footer/admin links on normal pages.
}

# Security-relevant response headers to capture
_SECURITY_HEADERS = {
    "server",
    "x-powered-by",
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "x-permitted-cross-domain-policies",
    "referrer-policy",
    "permissions-policy",
    "set-cookie",
    "www-authenticate",
    # F5 / BIG-IP specific
    "x-f5-asm",
    "x-f5-policy",
    "x-f5-block",
    "x-waf-event-info",
    "x-cnection",
    "x-forwarded-for",
    "x-real-ip",
    "via",
    "x-cache",
    "cf-ray",            # Cloudflare
    "x-request-id",
    "x-correlation-id",
}


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("waf_debug")


# =============================================================================
# Data stores (filled by the capture loop)
# =============================================================================

class CaptureStore:
    """Thread-safe store for everything we capture during the browser session."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.network_log: list[dict] = []       # all requests
        self.blocked_pages: list[dict] = []     # WAF-blocked pages only
        self.security_headers: dict[str, dict] = {}  # url -> {header: value}
        self.page_sources: dict[str, str] = {}  # url -> html
        self.console_logs: list[dict] = []      # browser console messages
        self.visited_urls: set[str] = set()

    def add_network(self, entry: dict) -> None:
        with self._lock:
            self.network_log.append(entry)

    def add_blocked(self, entry: dict) -> None:
        with self._lock:
            if entry not in self.blocked_pages:
                self.blocked_pages.append(entry)

    def add_security_headers(self, url: str, headers: dict) -> None:
        with self._lock:
            self.security_headers[url] = headers

    def add_page_source(self, url: str, html: str) -> None:
        with self._lock:
            self.page_sources[url] = html

    def add_console(self, entry: dict) -> None:
        with self._lock:
            self.console_logs.append(entry)

    def mark_visited(self, url: str) -> bool:
        """Return True if the URL hasn't been seen before."""
        with self._lock:
            if url in self.visited_urls:
                return False
            self.visited_urls.add(url)
            return True


# =============================================================================
# Chrome DevTools Protocol helpers
# =============================================================================

def _cdp(driver: webdriver.Chrome, cmd: str, params: dict | None = None) -> dict:
    """Execute a Chrome DevTools Protocol command and return the result."""
    return driver.execute_cdp_cmd(cmd, params or {})


def _enable_network_capture(driver: webdriver.Chrome) -> None:
    """Enable CDP network domain so we can see all requests/responses."""
    _cdp(driver, "Network.enable", {
        "maxTotalBufferSize": 100 * 1024 * 1024,
        "maxResourceBufferSize": 10 * 1024 * 1024,
    })
    _cdp(driver, "Log.enable")


def _get_all_cookies(driver: webdriver.Chrome) -> list[dict]:
    result = _cdp(driver, "Network.getAllCookies")
    return result.get("cookies", [])


def _get_local_storage(driver: webdriver.Chrome) -> dict:
    try:
        return driver.execute_script(
            "var s = {}; "
            "for (var i = 0; i < localStorage.length; i++) { "
            "  var k = localStorage.key(i); s[k] = localStorage.getItem(k); "
            "} return s;"
        ) or {}
    except Exception:
        return {}


def _get_session_storage(driver: webdriver.Chrome) -> dict:
    try:
        return driver.execute_script(
            "var s = {}; "
            "for (var i = 0; i < sessionStorage.length; i++) { "
            "  var k = sessionStorage.key(i); s[k] = sessionStorage.getItem(k); "
            "} return s;"
        ) or {}
    except Exception:
        return {}


def _get_moodle_config(driver: webdriver.Chrome) -> dict:
    """Extract Moodle JavaScript config objects from the current page."""
    try:
        raw = driver.execute_script(
            "var r = {}; "
            "try { r.cfg = JSON.parse(JSON.stringify(M.cfg)); } catch(e) {} "
            "try { r.wwwroot = M.cfg.wwwroot; } catch(e) {} "
            "try { r.sesskey = M.cfg.sesskey; } catch(e) {} "
            "try { r.userid = M.cfg.userid; } catch(e) {} "
            "try { r.contextid = M.cfg.contextid; } catch(e) {} "
            "try { r.theme = M.cfg.theme; } catch(e) {} "
            "try { r.yui = typeof Y !== 'undefined' ? Y.version : null; } catch(e) {} "
            "return r;"
        )
        return raw or {}
    except Exception:
        return {}


def _get_console_logs(driver: webdriver.Chrome) -> list[dict]:
    """Retrieve browser console logs via the WebDriver log interface."""
    try:
        entries = driver.get_log("browser")
        return entries or []
    except Exception:
        return []


def _get_performance_logs(driver: webdriver.Chrome) -> list[dict]:
    """Get CDP network events captured in the performance log."""
    try:
        entries = driver.get_log("performance")
        parsed = []
        for e in entries:
            try:
                msg = json.loads(e.get("message", "{}"))
                parsed.append(msg)
            except Exception:
                pass
        return parsed
    except Exception:
        return []


# =============================================================================
# Block type detection
# =============================================================================

def detect_block_type(html: str) -> str:
    """Classify the WAF/security block type from page HTML.

    The function extracts the ``<title>`` tag first and uses it for the
    "maintenance" check so that occurrences of "maintenance" buried in
    footers, admin menus, or help-link text on otherwise normal pages do
    NOT trigger a false-positive classification.
    """
    # ── Title-based "maintenance" check (most reliable, avoids false positives) ──
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.DOTALL)
    page_title = title_match.group(1).lower() if title_match else ""
    if "mainten" in page_title:
        return "maintenance"

    # ── Pattern-based checks for all other block types ──
    for block_type, patterns in _BLOCK_INDICATORS.items():
        for pat in patterns:
            if pat.search(html):
                return block_type
    return "ok"


def extract_f5_uuid(html: str) -> str:
    m = _F5_UUID_RE.search(html)
    return m.group(1) if m else ""


def _classify_from_headers(headers: dict) -> str:
    """Try to identify block type from response headers alone."""
    hints = []
    server = headers.get("server", "").lower()
    if "bigip" in server or "f5" in server:
        hints.append("F5 BIG-IP (Server header)")
    if any(k.lower().startswith("x-f5") for k in headers):
        hints.append("F5 header present")
    if "cf-ray" in {k.lower() for k in headers}:
        hints.append("Cloudflare (cf-ray)")
    if "x-waf-event-info" in {k.lower() for k in headers}:
        hints.append("WAF event-info header")
    return ", ".join(hints) if hints else "no WAF header signature"


# =============================================================================
# Per-page capture
# =============================================================================

def capture_page(driver: webdriver.Chrome, store: CaptureStore) -> None:
    """Capture everything we can from the currently loaded page."""
    url = driver.current_url
    if not store.mark_visited(url):
        return  # already captured this URL

    now_il = datetime.now(TZ_IL)
    log.info("Capturing page: %s", url)

    # ── page source ──
    try:
        html = driver.page_source or ""
    except Exception:
        html = ""

    store.add_page_source(url, html)

    # ── WAF / block detection ──
    block_type = detect_block_type(html)
    f5_uuid = extract_f5_uuid(html)

    if block_type != "ok" or f5_uuid:
        entry: dict = {
            "url": url,
            "timestamp_il": now_il.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "block_type": block_type,
            "f5_support_uuid": f5_uuid,
            "page_title": driver.title,
            "html_excerpt": html[:3000],
        }
        store.add_blocked(entry)
        log.warning(
            "⚠️  BLOCK DETECTED  url=%s  type=%s  uuid=%s",
            url, block_type, f5_uuid or "(none)",
        )

    # ── security headers via requests (mirrors browser GET without credentials) ──
    try:
        r = requests.get(
            url,
            headers={
                "User-Agent": driver.execute_script("return navigator.userAgent;"),
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Language": "he-IL,he;q=0.9,en-US;q=0.8",
            },
            timeout=15,
            allow_redirects=True,
        )
        sec_headers = {
            k.lower(): v
            for k, v in r.headers.items()
            if k.lower() in _SECURITY_HEADERS or k.lower().startswith("x-f5")
        }
        sec_headers["_status_code"] = str(r.status_code)
        sec_headers["_final_url"] = r.url
        sec_headers["_waf_header_hint"] = _classify_from_headers(r.headers)
        store.add_security_headers(url, sec_headers)
    except Exception as exc:
        store.add_security_headers(url, {"_error": str(exc)})

    # ── Moodle JS config ──
    moodle_cfg = _get_moodle_config(driver)
    if moodle_cfg:
        log.info("Moodle config: sesskey=%s  userid=%s",
                 moodle_cfg.get("sesskey", "?"), moodle_cfg.get("userid", "?"))

    # ── console logs ──
    for entry in _get_console_logs(driver):
        store.add_console({
            "url": url,
            "timestamp_il": now_il.strftime("%H:%M:%S"),
            **entry,
        })


# =============================================================================
# Performance-log network harvester
# =============================================================================

_SEEN_REQUEST_IDS: set[str] = set()


def harvest_network_from_perf_log(driver: webdriver.Chrome, store: CaptureStore) -> None:
    """
    Parse Chrome performance log entries to build a full network request log
    including request and response headers.
    """
    for msg in _get_performance_logs(driver):
        try:
            method = msg.get("message", {}).get("method", "")
            params = msg.get("message", {}).get("params", {})

            if method == "Network.responseReceived":
                resp = params.get("response", {})
                req_id = params.get("requestId", "")
                if req_id in _SEEN_REQUEST_IDS:
                    continue
                _SEEN_REQUEST_IDS.add(req_id)

                url = resp.get("url", "")
                status = resp.get("status", 0)
                resp_headers = resp.get("headers", {})
                req_headers = resp.get("requestHeaders", {})

                # Capture security headers
                sec = {
                    k.lower(): v
                    for k, v in resp_headers.items()
                    if k.lower() in _SECURITY_HEADERS or k.lower().startswith("x-f5")
                }

                entry = {
                    "request_id": req_id,
                    "url": url,
                    "status": status,
                    "mime_type": resp.get("mimeType", ""),
                    "remote_ip": resp.get("remoteIPAddress", ""),
                    "security_headers": sec,
                    "request_headers": dict(req_headers),
                    "response_headers": dict(resp_headers),
                    "waf_hint": _classify_from_headers(resp_headers),
                    "timestamp_il": datetime.now(TZ_IL).strftime("%H:%M:%S"),
                }
                store.add_network(entry)

                # Check response for WAF block
                if status in (200,) and any(h.lower().startswith("x-f5") for h in resp_headers):
                    log.info("F5 header on: %s (status=%s)", url, status)

        except Exception:
            pass


# =============================================================================
# Output / save
# =============================================================================

def _slug(url: str) -> str:
    """Turn a URL into a safe filename."""
    parsed = urlparse(url)
    slug = (parsed.netloc + parsed.path).replace("/", "_").replace(".", "_")
    return slug[:80]


def save_all(store: CaptureStore, driver: webdriver.Chrome, out_dir: Path) -> Path:
    """Save all captured data to `out_dir` and return it."""
    out_dir.mkdir(parents=True, exist_ok=True)
    now_il = datetime.now(TZ_IL)

    # ── cookies ──
    cookies = _get_all_cookies(driver)
    (out_dir / "cookies.json").write_text(
        json.dumps(cookies, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    log.info("Saved %d cookies", len(cookies))

    # ── storage ──
    storage = {
        "localStorage": _get_local_storage(driver),
        "sessionStorage": _get_session_storage(driver),
    }
    (out_dir / "storage.json").write_text(
        json.dumps(storage, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # ── Moodle config from current page ──
    moodle_cfg = _get_moodle_config(driver)
    (out_dir / "moodle_config.json").write_text(
        json.dumps(moodle_cfg, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # ── network log ──
    with store._lock:
        net_log = list(store.network_log)
    (out_dir / "network_log.json").write_text(
        json.dumps(net_log, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    log.info("Saved %d network entries", len(net_log))

    # ── blocked pages ──
    with store._lock:
        blocked = list(store.blocked_pages)
    (out_dir / "blocked_pages.json").write_text(
        json.dumps(blocked, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # ── security headers ──
    with store._lock:
        sec_hdrs = dict(store.security_headers)
    (out_dir / "security_headers.json").write_text(
        json.dumps(sec_hdrs, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # ── console log ──
    with store._lock:
        con_log = list(store.console_logs)
    lines = [
        f"[{e.get('timestamp_il','')}] [{e.get('level','')}] {e.get('url','')} | {e.get('message','')}"
        for e in con_log
    ]
    (out_dir / "console_log.txt").write_text("\n".join(lines), encoding="utf-8")

    # ── page sources ──
    src_dir = out_dir / "page_sources"
    src_dir.mkdir(exist_ok=True)
    with store._lock:
        pages = dict(store.page_sources)
    for url, html in pages.items():
        fname = _slug(url) + ".html"
        (src_dir / fname).write_text(html, encoding="utf-8")
    log.info("Saved %d page sources", len(pages))

    # ── summary ──
    summary = _build_summary(store, cookies, moodle_cfg, now_il)
    (out_dir / "summary.txt").write_text(summary, encoding="utf-8")
    print("\n" + "=" * 70)
    print(summary)
    print("=" * 70)

    return out_dir


def _build_summary(
    store: CaptureStore,
    cookies: list[dict],
    moodle_cfg: dict,
    now_il: datetime,
) -> str:
    with store._lock:
        blocked = list(store.blocked_pages)
        net_count = len(store.network_log)
        visited = sorted(store.visited_urls)
        sec_hdrs = dict(store.security_headers)

    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("TAU Moodle WAF Diagnostic Summary")
    lines.append(f"Generated: {now_il.strftime('%Y-%m-%d %H:%M:%S %Z')} (UTC+3)")
    lines.append("=" * 70)

    # ── block findings ──
    if blocked:
        lines.append(f"\n🚫  BLOCK/WAF PAGES DETECTED: {len(blocked)}")
        for b in blocked:
            lines.append(f"\n  URL       : {b['url']}")
            lines.append(f"  Timestamp : {b['timestamp_il']}")
            lines.append(f"  UTC       : {b['timestamp_utc']}")
            lines.append(f"  Block type: {b['block_type']}")
            if b.get("f5_support_uuid"):
                lines.append(f"  F5 UUID   : {b['f5_support_uuid']}")
                lines.append("  ℹ️  Share this UUID with TAU support to identify the exact WAF rule.")
            lines.append(f"  Page title: {b.get('page_title', '')}")
    else:
        lines.append("\n✅  No WAF-block pages detected during this session.")

    # ── security headers summary ──
    lines.append("\n── Security Headers by URL ──────────────────────────────────────")
    for url, hdrs in list(sec_hdrs.items())[:20]:
        lines.append(f"\n  {url[:80]}")
        for k, v in hdrs.items():
            if not k.startswith("_"):
                lines.append(f"    {k}: {v[:120]}")
        if "_waf_header_hint" in hdrs:
            lines.append(f"    → WAF hint: {hdrs['_waf_header_hint']}")
        if "_status_code" in hdrs:
            lines.append(f"    → HTTP status: {hdrs['_status_code']}")

    # ── cookies summary ──
    tau_cookies = [c for c in cookies if "tau.ac.il" in c.get("domain", "")]
    lines.append(f"\n── Cookies: {len(tau_cookies)} tau.ac.il cookies found ──────────────────")
    for c in tau_cookies:
        secure = "🔒" if c.get("secure") else "⚠️ NOT SECURE"
        httponly = "🔒 httpOnly" if c.get("httpOnly") else "⚠️ accessible from JS"
        lines.append(f"  {c['name']:40s}  {secure}  {httponly}  domain={c.get('domain')}")

    # ── Moodle config ──
    if moodle_cfg.get("sesskey"):
        lines.append(f"\n── Moodle Session ─────────────────────────────────────────────────")
        lines.append(f"  sesskey  : {moodle_cfg.get('sesskey')}")
        lines.append(f"  userid   : {moodle_cfg.get('userid')}")
        lines.append(f"  wwwroot  : {moodle_cfg.get('wwwroot')}")
        lines.append(f"  theme    : {moodle_cfg.get('theme')}")

    # ── network stats ──
    lines.append(f"\n── Network ────────────────────────────────────────────────────────")
    lines.append(f"  Total requests captured: {net_count}")
    lines.append(f"  Unique pages visited   : {len(visited)}")
    for v in visited[:30]:
        lines.append(f"    {v}")

    # ── guidance ──
    lines.append("\n── How to use this data ───────────────────────────────────────────")
    lines.append(
        "  1. blocked_pages.json contains the exact F5 Support ID(s) – share these with")
    lines.append(
        "     TAU IT support (support@tau.ac.il) so they can look up the WAF rule in their logs.")
    lines.append(
        "  2. security_headers.json shows which WAF headers the server sends on each request.")
    lines.append(
        "  3. network_log.json has full request/response headers for every resource.")
    lines.append(
        "  4. If the F5 UUID appears: this is a bot-score or IP-reputation block by F5 BIG-IP ASM.")
    lines.append(
        "  5. If only 'access_denied' (no UUID): could be a Geo/ASN or internal policy rule.")
    lines.append(
        "  6. GitHub Actions runner IPs belong to Microsoft/Azure ASNs – TAU may block all cloud ASNs.")

    return "\n".join(lines)


# =============================================================================
# Main capture loop
# =============================================================================

def _build_driver() -> webdriver.Chrome:
    """Build a visible (non-headless) Chrome with CDP logging enabled."""
    opts = Options()
    # Keep browser visible so user can interact
    opts.add_argument("--disable-notifications")
    opts.add_argument("--disable-popup-blocking")
    opts.add_argument("--start-maximized")
    # Enable DevTools performance + browser console logging
    opts.set_capability("goog:loggingPrefs", {
        "browser": "ALL",
        "performance": "ALL",
    })
    # Anti-fingerprinting: do NOT add --headless; do NOT add automation flags
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)
    opts.add_argument("--disable-blink-features=AutomationControlled")

    driver = webdriver.Chrome(options=opts)
    driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
        "source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
    })
    return driver


def _is_driver_alive(driver: webdriver.Chrome) -> bool:
    try:
        _ = driver.current_url
        return True
    except Exception:
        return False


def _capture_loop(
    driver: webdriver.Chrome,
    store: CaptureStore,
    stop_event: threading.Event,
) -> None:
    """Background thread: continuously capture page data while the user browses."""
    while not stop_event.is_set():
        if not _is_driver_alive(driver):
            log.info("Browser closed – stopping capture loop.")
            stop_event.set()
            break
        try:
            capture_page(driver, store)
            harvest_network_from_perf_log(driver, store)
        except Exception as exc:
            log.debug("Capture error (ignored): %s", exc)
        stop_event.wait(POLL_INTERVAL)


def main() -> None:
    ts = datetime.now(TZ_IL).strftime("%Y%m%d_%H%M%S")

    # Output location.  Defaults to the project-specific Windows path below.
    # Override by setting the WAF_RESULTS_DIR environment variable, e.g.:
    #   set WAF_RESULTS_DIR=D:\my_results        (Windows)
    #   export WAF_RESULTS_DIR=/tmp/waf_results  (Linux/Mac)
    _DEFAULT_RESULTS_BASE = Path(
        r"C:\Users\edeni\OneDrive\PythonStudies\python uses"
        r"\extract_files_from_moodle\understanding how moodle security works"
        r"\results\GITHUB"
    )
    env_override = os.environ.get("WAF_RESULTS_DIR", "")
    results_base = Path(env_override) if env_override else _DEFAULT_RESULTS_BASE
    out_dir = results_base / f"waf_debug_{ts}"

    print("=" * 70)
    print("TAU Moodle WAF Diagnostic Tool")
    print("=" * 70)
    print(f"\nStarting Chrome browser → {START_URL}")
    print(f"Output folder          → {out_dir}")
    print(f"\nInstructions:")
    print("  1. A Chrome window will open automatically.")
    print("  2. Log in to Moodle manually and browse a few course pages.")
    print("  3. Press Enter here (in the terminal) when you're done browsing.")
    print(f"  4. All diagnostic data will be saved to:  {out_dir}/")
    print(f"\nMax wait time: {WAIT_MINUTES} minutes (then saves automatically).")
    print()

    # ── open browser ──────────────────────────────────────────────────────────
    driver = _build_driver()
    _enable_network_capture(driver)

    store = CaptureStore()
    stop_event = threading.Event()

    # start background capture thread
    capture_thread = threading.Thread(
        target=_capture_loop, args=(driver, store, stop_event), daemon=True
    )
    capture_thread.start()

    # navigate to start URL
    try:
        driver.get(START_URL)
    except Exception as exc:
        log.warning("Could not load %s: %s", START_URL, exc)

    # ── wait for user to finish browsing ─────────────────────────────────────
    log.info("Waiting for user to browse (max %d min). Press Enter to finish early.",
             WAIT_MINUTES)

    def _wait_for_enter() -> None:
        try:
            input()
        except EOFError:
            pass
        stop_event.set()

    enter_thread = threading.Thread(target=_wait_for_enter, daemon=True)
    enter_thread.start()

    deadline = time.time() + WAIT_MINUTES * 60
    while not stop_event.is_set() and time.time() < deadline:
        if not _is_driver_alive(driver):
            log.info("Browser window closed.")
            stop_event.set()
            break
        remaining = int(deadline - time.time())
        if remaining % 60 == 0 and remaining > 0:
            log.info("Still capturing… %d min remaining. Press Enter when done.", remaining // 60)
        time.sleep(1)

    stop_event.set()

    # ── final capture before saving ───────────────────────────────────────────
    if _is_driver_alive(driver):
        try:
            capture_page(driver, store)
            harvest_network_from_perf_log(driver, store)
        except Exception:
            pass

    # ── save everything ───────────────────────────────────────────────────────
    log.info("Saving diagnostic data to %s …", out_dir)
    try:
        saved = save_all(store, driver, out_dir)
        print(f"\n✅  Saved to: {saved}/")
    except Exception as exc:
        log.error("Error saving data: %s", exc)

    # ── close browser ─────────────────────────────────────────────────────────
    try:
        driver.quit()
    except Exception:
        pass


if __name__ == "__main__":
    main()
