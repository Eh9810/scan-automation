# -*- coding: utf-8 -*-
"""
TAU Moodle scanner (GitHub Actions-ready):
- Login to TAU NIDP (SSO) via Selenium headless Chrome
- Go to My Courses
- Scan course pages for pluginfile links + resolve resource/folder/assign
- Use HTTP Last-Modified as "שינוי אחרון"
- Check only what changed since last run (stored in last_run.json)
- If there are updates -> send Telegram message (no updates -> send nothing)
- If there is an error -> send Telegram message with the GitHub Actions run link + traceback
"""

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import unquote, urljoin, urlparse
import json
import logging
import os
import re
import time
import traceback

import requests
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

try:
    from bs4 import BeautifulSoup
except ImportError:
    raise SystemExit("Missing bs4. Install: pip install beautifulsoup4")

try:
    from zoneinfo import ZoneInfo
except ImportError:
    raise SystemExit("Missing zoneinfo (Python 3.9+).")


class MoodleMaintenanceError(Exception):
    """Raised when Moodle is showing a maintenance page."""


# ==========================
# CONFIG
# ==========================

LOGIN_URL = "https://nidp.tau.ac.il/nidp/saml2/sso?id=10&sid=0&option=credential&sid=0"
MY_COURSES_URL = "https://moodle.tau.ac.il/local/mycourses/"
MOODLE_DASHBOARD_URL = "https://moodle.tau.ac.il/my/"

TZ_IL = ZoneInfo("Asia/Jerusalem")
WAIT_SEC = 30
HEADLESS = True

STATE_FILE = "last_run.json"  # will be created/updated in repo
COOKIES_FILE = "moodle_cookies.json"  # listed in .gitignore; persisted via actions/cache
MAINTENANCE_NOTIFY_THROTTLE_HOURS = 4  # send at most one maintenance alert per this many hours
MAINTENANCE_RETRY_COUNT = 2      # retry this many extra times before giving up on maintenance
MAINTENANCE_RETRY_DELAY_SEC = 60  # seconds to wait between maintenance retries

logger = logging.getLogger(__name__)

# Shared browser User-Agent used for all HTTP sessions.
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# ==========================
# SECRETS (from GitHub Actions)
# ==========================
# IMPORTANT: do NOT hardcode secrets here.
# Put them in GitHub -> Settings -> Secrets and variables -> Actions -> Secrets.
USERNAME = os.environ.get("MOODLE_USERNAME", "")
USER_ID = os.environ.get("MOODLE_USER_ID", "")
PASSWORD = os.environ.get("MOODLE_PASSWORD", "")

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# Set by GitHub Actions; "workflow_dispatch" means the user triggered the run manually.
GITHUB_EVENT_NAME = os.environ.get("GITHUB_EVENT_NAME", "")


# ==========================
# DATA
# ==========================

@dataclass(frozen=True)
class FoundFile:
    course_name_raw: str
    course_name_display: str
    file_name: str
    last_modified_il: datetime
    link: str


# ==========================
# HELPERS
# ==========================

def _course_display_name(raw: str) -> str:
    """
    Convert '05092843 - אנליזה הרמונית' -> 'אנליזה הרמונית'
    Keep others as-is.
    """
    s = (raw or "").strip()
    if " - " in s:
        left, right = s.split(" - ", 1)
        if re.fullmatch(r"\d{6,}", left.strip()):
            s = right.strip()
    return s


def _safe_filename_from_url(url: str) -> str:
    path = urlparse(url).path
    name = path.rsplit("/", 1)[-1]
    name = unquote(name).strip()
    return name or url


def _parse_http_last_modified(headers) -> datetime | None:
    lm = headers.get("Last-Modified") or headers.get("last-modified")
    if not lm:
        return None
    try:
        dt = parsedate_to_datetime(lm)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(TZ_IL)
    except Exception:
        return None


def _session_from_selenium_cookies(driver: webdriver.Chrome) -> requests.Session:
    s = requests.Session()
    try:
        ua = driver.execute_script("return navigator.userAgent;")
        s.headers.update({"User-Agent": ua})
    except Exception:
        pass

    for c in driver.get_cookies():
        s.cookies.set(
            name=c.get("name"),
            value=c.get("value"),
            domain=c.get("domain"),
            path=c.get("path", "/"),
        )
    return s


# ==========================
# HTTP-BASED SAML LOGIN (no Selenium)
# ==========================

# Known NIDP form-field names for each credential type
_NIDP_USER_NAMES = ["Ecom_User_ID", "Ecom_UserID", "Ecom_Username", "username", "user"]
_NIDP_PID_NAMES = ["Ecom_Taz", "Ecom_User_Pid", "Ecom_Pid", "pid", "tz"]
_NIDP_PASS_NAMES = ["Ecom_Password", "Ecom_Pass", "password", "pass"]


def _fill_nidp_credentials(form_data: dict) -> None:
    """Inject TAU credentials into an HTML-form data dict (in-place)."""
    for key in _NIDP_USER_NAMES:
        if key in form_data:
            form_data[key] = USERNAME
            break
    for key in _NIDP_PID_NAMES:
        if key in form_data:
            form_data[key] = USER_ID
            break
    for key in _NIDP_PASS_NAMES:
        if key in form_data:
            form_data[key] = PASSWORD
            break


def _form_to_dict(form, base_url: str) -> tuple:
    """
    Extract (action_url, {name: value}) from a BeautifulSoup <form> element.
    Resolves relative action URLs against base_url.
    """
    action = form.get("action") or base_url
    if not action.startswith("http"):
        action = urljoin(base_url, action)
    data = {
        inp["name"]: inp.get("value", "")
        for inp in form.find_all("input")
        if inp.get("name")
    }
    return action, data


def _http_saml_login() -> "requests.Session | None":
    """
    Authenticate against TAU NIDP via a plain-HTTP SAML SSO handshake
    (no browser / no Selenium).

    Steps:
      1. GET the NIDP SSO URL  → HTML login form
      2. POST credentials      → NIDP returns auto-submit SAMLResponse form
      3. POST SAMLResponse     → Moodle ACS sets session cookie + redirects
      4. Verify we landed on a real, non-maintenance Moodle page

    Returns a requests.Session with valid Moodle cookies on success, or None on
    any failure so the caller can fall back to Selenium.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": _BROWSER_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7",
    })

    try:
        # ── 1. Fetch NIDP login page ──────────────────────────────────────────
        logger.info("HTTP login step 1: GET %s", LOGIN_URL)
        resp = session.get(LOGIN_URL, timeout=30)
        resp.raise_for_status()
        logger.info("HTTP login step 1: landed on %s (status=%s)", resp.url, resp.status_code)

        soup = BeautifulSoup(resp.text, "html.parser")
        # Prefer the form that has a password field; fall back to the first form.
        form = None
        for f in soup.find_all("form"):
            if f.find("input", {"type": "password"}):
                form = f
                break
        if not form:
            form = soup.find("form")
        if not form:
            title = soup.find("title")
            logger.warning(
                "HTTP login: no <form> on NIDP login page (title=%r) – cannot proceed",
                title.get_text() if title else "",
            )
            return None

        action, data = _form_to_dict(form, resp.url)
        logger.info("HTTP login step 1: form action=%s, fields=%s", action, list(data.keys()))
        _fill_nidp_credentials(data)

        # ── 2. Submit credentials to NIDP ────────────────────────────────────
        logger.info("HTTP login step 2: POST credentials to %s", action)
        resp = session.post(action, data=data, timeout=30)
        resp.raise_for_status()
        logger.info("HTTP login step 2: response URL=%s status=%s", resp.url, resp.status_code)

        # ── 3. POST SAMLResponse to Moodle ACS ───────────────────────────────
        soup = BeautifulSoup(resp.text, "html.parser")
        saml_input = soup.find("input", {"name": "SAMLResponse"})
        if not saml_input:
            title = soup.find("title")
            logger.warning(
                "HTTP login: no SAMLResponse in NIDP response "
                "(wrong credentials or JS-only flow). Page title: %r",
                title.get_text() if title else "",
            )
            return None

        saml_form = saml_input.find_parent("form")
        acs_url, saml_data = _form_to_dict(saml_form, resp.url)
        logger.info("HTTP login step 3: POST SAMLResponse to Moodle ACS %s", acs_url)
        resp = session.post(acs_url, data=saml_data, timeout=30)
        resp.raise_for_status()
        logger.info("HTTP login step 3: response URL=%s status=%s", resp.url, resp.status_code)

        # ── 4. Verify Moodle landing page ────────────────────────────────────
        if "moodle.tau.ac.il" not in resp.url:
            logger.warning("HTTP login: unexpected landing URL: %s", resp.url)
            return None

        soup = BeautifulSoup(resp.text, "html.parser")
        title_el = soup.find("title")
        title_text = title_el.get_text() if title_el else ""
        # "mainten" matches both the correct spelling and the TAU server's misspelling "Maintenence"
        if "mainten" in title_text.lower():
            logger.warning(
                "HTTP login: maintenance page on landing URL %s (title=%r)",
                resp.url, title_text,
            )
            return None

        logger.info("HTTP login succeeded – landed on %s (title=%r)", resp.url, title_text)
        return session

    except Exception as exc:
        logger.warning("HTTP login failed: %s", exc)
        return None


def _http_head_follow(session: requests.Session, url: str) -> requests.Response | None:
    try:
        r = session.head(url, allow_redirects=True, timeout=30)
        if r.status_code in (403, 405) or (r.status_code >= 400 and "Last-Modified" not in r.headers):
            r = session.get(url, allow_redirects=True, timeout=30, stream=True)
        return r
    except Exception:
        return None


def _http_get_html(session: requests.Session, url: str) -> str | None:
    try:
        r = session.get(url, allow_redirects=True, timeout=40)
        if r.status_code >= 400:
            return None
        return r.text
    except Exception:
        return None


def _get_courses_via_http(session: requests.Session) -> list:
    """
    Fetch the enrolled-course list using a plain-HTTP session (no Selenium).

    Tries MY_COURSES_URL first, then MOODLE_DASHBOARD_URL as a fallback.
    Returns a de-duplicated list of (raw_course_name, course_url) tuples.
    """
    for url in (MY_COURSES_URL, MOODLE_DASHBOARD_URL):
        html = _http_get_html(session, url)
        if not html:
            logger.warning("HTTP courses: could not fetch %s", url)
            continue

        soup = BeautifulSoup(html, "html.parser")
        title_el = soup.find("title")
        title_text = (title_el.get_text() if title_el else "").lower()
        if "mainten" in title_text:
            logger.warning(
                "HTTP courses: maintenance page at %s (title=%r) – trying fallback",
                url, title_text,
            )
            continue

        courses: list = []
        seen: set = set()
        for a in soup.find_all("a", href=True):
            href: str = a["href"]
            if "course/view.php?id=" not in href:
                continue
            name = a.get_text(strip=True)
            if name and href not in seen:
                courses.append((name, href))
                seen.add(href)

        if courses:
            logger.info("HTTP courses: found %d unique courses at %s", len(courses), url)
            return courses

        logger.warning("HTTP courses: no courses found at %s – trying fallback", url)

    return []


def _extract_pluginfile_links_from_html(html: str) -> list[tuple[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    out = []
    for a in soup.select("a[href*='pluginfile.php']"):
        href = a.get("href")
        if not href:
            continue
        text = (a.get_text(" ", strip=True) or "").strip()
        out.append((href, text))
    return out


def _extract_activity_links_from_course_html(html: str) -> tuple[set[str], set[str]]:
    soup = BeautifulSoup(html, "html.parser")
    pluginfiles = set()
    activity_pages = set()

    for a in soup.select("a[href]"):
        href = a.get("href")
        if not href:
            continue

        if "moodle.tau.ac.il/pluginfile.php/" in href:
            pluginfiles.add(href)
            continue

        if "moodle.tau.ac.il/mod/resource/view.php" in href:
            activity_pages.add(href)
        elif "moodle.tau.ac.il/mod/folder/view.php" in href:
            activity_pages.add(href)
        elif "moodle.tau.ac.il/mod/assign/view.php" in href:
            activity_pages.add(href)

    return pluginfiles, activity_pages


def _resolve_resource_view_to_file(session: requests.Session, view_url: str) -> list[str]:
    urls: list[str] = []

    if "redirect=" not in view_url:
        joiner = "&" if "?" in view_url else "?"
        test_url = view_url + f"{joiner}redirect=1"
    else:
        test_url = view_url

    r = _http_head_follow(session, test_url)
    if r is not None and r.url and "pluginfile.php" in r.url:
        urls.append(r.url)
        return urls

    html = _http_get_html(session, view_url)
    if not html:
        return urls

    for href, _txt in _extract_pluginfile_links_from_html(html):
        urls.append(href)

    return list(dict.fromkeys(urls))


def _get_last_modified_for_file(session: requests.Session, file_url: str) -> datetime | None:
    r = _http_head_follow(session, file_url)
    if not r:
        return None
    return _parse_http_last_modified(r.headers)


def _normalize_link_for_print(original_link: str, pluginfile_link: str) -> str:
    if (
        "mod/resource/view.php" in original_link
        or "mod/folder/view.php" in original_link
        or "mod/assign/view.php" in original_link
    ):
        return original_link
    return pluginfile_link


def _format_line(item: FoundFile) -> str:
    return (
        f"{item.course_name_display}\t | "
        f"שם הקובץ: {item.file_name}\t | "
        f"שינוי אחרון: {item.last_modified_il.strftime('%d.%m.%Y %H:%M')}\t | "
        f"קישור: {item.link}"
    )


# ==========================
# STATE (last run)
# ==========================

def _load_state_data() -> dict:
    """Read the raw JSON state dict (returns {} if missing or unreadable)."""
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _parse_state_dt(iso: str | None) -> datetime | None:
    """Parse an ISO datetime string from the state file; return None on failure."""
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=TZ_IL)
        return dt.astimezone(TZ_IL)
    except Exception:
        return None


def load_last_run() -> datetime:
    # default: last hour (so first run won't spam months)
    fallback = datetime.now(TZ_IL) - timedelta(hours=1)
    dt = _parse_state_dt(_load_state_data().get("last_run_iso"))
    return dt if dt is not None else fallback


def load_last_maintenance_notified() -> datetime | None:
    """Return when we last sent a maintenance notification, or None if never."""
    return _parse_state_dt(_load_state_data().get("last_maintenance_notified_iso"))


def _save_state(updates: dict) -> None:
    """Merge *updates* into the existing state file and write it back."""
    data = _load_state_data()
    data.update(updates)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def save_last_run(run_start: datetime) -> None:
    _save_state({"last_run_iso": run_start.astimezone(TZ_IL).isoformat()})


def save_maintenance_notified(dt: datetime) -> None:
    _save_state({"last_maintenance_notified_iso": dt.astimezone(TZ_IL).isoformat()})


# ==========================
# SESSION COOKIE PERSISTENCE
# (cached by GitHub Actions; COOKIES_FILE is in .gitignore)
# ==========================

def save_http_session_cookies(session: requests.Session) -> None:
    """Persist Moodle session cookies to COOKIES_FILE for reuse in the next run."""
    cookies = [
        {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path}
        for c in session.cookies
        if c.domain and "tau.ac.il" in c.domain
    ]
    if not cookies:
        logger.warning("save_http_session_cookies: no tau.ac.il cookies in session to save")
        return
    try:
        with open(COOKIES_FILE, "w", encoding="utf-8") as f:
            json.dump(cookies, f, ensure_ascii=False)
        logger.info("Saved %d session cookies to %s", len(cookies), COOKIES_FILE)
    except Exception as exc:
        logger.warning("Could not save cookies: %s", exc)


def load_http_session_from_cookies() -> "requests.Session | None":
    """
    Try to restore a Moodle HTTP session from COOKIES_FILE (written by the previous run).
    Verifies the cookies are still valid by fetching the Moodle dashboard.
    Returns a working requests.Session, or None if the file is missing/cookies are expired.
    """
    if not os.path.exists(COOKIES_FILE):
        logger.info("Cookie file %s not found – fresh login required", COOKIES_FILE)
        return None
    try:
        with open(COOKIES_FILE, encoding="utf-8") as f:
            saved = json.load(f)
    except Exception as exc:
        logger.warning("Cookie file unreadable: %s", exc)
        return None

    session = requests.Session()
    session.headers.update({
        "User-Agent": _BROWSER_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7",
    })
    for c in saved:
        session.cookies.set(
            name=c["name"],
            value=c["value"],
            domain=c.get("domain"),
            path=c.get("path", "/"),
        )

    # Verify the session is still valid against the Moodle dashboard.
    logger.info("Verifying saved cookies against %s", MOODLE_DASHBOARD_URL)
    html = _http_get_html(session, MOODLE_DASHBOARD_URL)
    if not html:
        logger.warning("Cookie reuse: Moodle dashboard unreachable")
        return None

    soup = BeautifulSoup(html, "html.parser")
    title_el = soup.find("title")
    title_text = (title_el.get_text() if title_el else "").lower()

    if "mainten" in title_text:
        logger.warning("Cookie reuse: maintenance page (title=%r)", title_text)
        return None
    if "log in" in title_text or "login" in title_text or "sign in" in title_text:
        logger.warning("Cookie reuse: redirected to login – cookies expired (title=%r)", title_text)
        return None

    logger.info("Cookie reuse: session still valid (dashboard title=%r)", title_text)
    return session


# ==========================
# TELEGRAM
# ==========================

def telegram_send(text: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("Telegram secrets missing; skipping send.")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "disable_web_page_preview": True,
    }
    r = requests.post(url, json=payload, timeout=30)
    print(r.text)


def telegram_send_many(lines: list[str], header: str) -> None:
    # Telegram limit ~4096 chars per message → split safely
    max_len = 3800
    chunk = header + "\n"
    for line in lines:
        if len(chunk) + len(line) + 1 > max_len:
            telegram_send(chunk)
            chunk = header + "\n"
        chunk += line + "\n"
    if chunk.strip():
        telegram_send(chunk)


def github_run_url() -> str:
    # https://github.com/<owner>/<repo>/actions/runs/<run_id>
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if repo and run_id:
        return f"https://github.com/{repo}/actions/runs/{run_id}"
    return ""


# ==========================
# SELENIUM: DRIVER + LOGIN
# ==========================

def build_driver() -> webdriver.Chrome:
    options = Options()
    options.add_argument("--disable-notifications")
    options.add_argument("--disable-popup-blocking")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    # Anti-fingerprinting: hide automation indicators from the server
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)
    if HEADLESS:
        options.add_argument("--headless=new")
    # Selenium Manager will download/install matching driver automatically on GitHub runners
    driver = webdriver.Chrome(options=options)
    # Mask navigator.webdriver so the server can't detect headless Chrome
    driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
        "source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
    })
    return driver


def _find_any(driver: webdriver.Chrome, by: By, values: list[str]):
    """
    Return the first element that is BOTH displayed and enabled.
    (Prevents picking hidden/overlayed fields that cause ElementNotInteractableException)
    """
    for v in values:
        try:
            el = driver.find_element(by, v)
            if el.is_displayed() and el.is_enabled():
                return el
        except Exception:
            continue
    return None


def maybe_login_nidp(driver: webdriver.Chrome) -> None:
    """
    Fill the TAU NIDP SSO form if it appears.
    Robust against multiple possible field IDs AND hidden duplicates.
    """
    wait = WebDriverWait(driver, WAIT_SEC)

    user_ids = ["Ecom_User_ID", "Ecom_UserID", "Ecom_Username", "username", "user"]
    pid_ids  = ["Ecom_Taz", "Ecom_User_Pid", "Ecom_Pid", "pid", "tz"]
    pass_ids = ["Ecom_Password", "Ecom_Pass", "password", "pass"]

    def any_visible_login_field_present(d):
        return (_find_any(d, By.ID, user_ids) is not None) or (_find_any(d, By.ID, pass_ids) is not None)

    try:
        wait.until(any_visible_login_field_present)
    except Exception:
        # no login form detected
        return

    def _safe_fill(el, value: str):
        # scroll + focus
        try:
            driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        except Exception:
            pass

        try:
            el.click()
        except Exception:
            try:
                driver.execute_script("arguments[0].click();", el)
            except Exception:
                pass

        # clear via keyboard (more reliable than clear())
        try:
            el.send_keys(Keys.CONTROL, "a")
            el.send_keys(Keys.BACKSPACE)
            el.send_keys(value)
            return
        except Exception:
            # last resort: set via JS + fire input/change
            driver.execute_script(
                "arguments[0].value = arguments[1];"
                "arguments[0].dispatchEvent(new Event('input', {bubbles:true}));"
                "arguments[0].dispatchEvent(new Event('change', {bubbles:true}));",
                el, value
            )

    user_field = _find_any(driver, By.ID, user_ids)
    if user_field:
        _safe_fill(user_field, USERNAME)

    pid_field = _find_any(driver, By.ID, pid_ids)
    if pid_field:
        _safe_fill(pid_field, USER_ID)

    pass_field = _find_any(driver, By.ID, pass_ids)
    if not pass_field:
        return

    _safe_fill(pass_field, PASSWORD)
    pass_field.send_keys(Keys.RETURN)


def ensure_on_moodle(driver: webdriver.Chrome) -> None:
    wait = WebDriverWait(driver, WAIT_SEC)

    def reached_moodle_or_portal(d):
        url = d.current_url.lower()
        return ("moodle.tau.ac.il" in url) or ("nidp.tau.ac.il/nidp/portal" in url)

    try:
        wait.until(reached_moodle_or_portal)
    except Exception:
        pass

    if "nidp.tau.ac.il/nidp/portal" in driver.current_url.lower():
        driver.get(MY_COURSES_URL)

    wait.until(lambda d: "moodle.tau.ac.il" in d.current_url.lower())


def click_login_if_guest(driver: webdriver.Chrome) -> bool:
    selectors = [
        "#usernavigation a[href*='/login/index.php']",
        "a[href='https://moodle.tau.ac.il/login/index.php']",
        "a[href*='moodle.tau.ac.il/login/index.php']",
    ]

    for sel in selectors:
        try:
            el = driver.find_element(By.CSS_SELECTOR, sel)
            if el and el.is_displayed():
                driver.execute_script("arguments[0].click();", el)
                return True
        except Exception:
            pass

    try:
        els = driver.find_elements(By.XPATH, "//a[contains(normalize-space(.), 'התחבר')]")
        for el in els:
            if el.is_displayed():
                driver.execute_script("arguments[0].click();", el)
                return True
    except Exception:
        pass

    return False


_COURSE_CSS_SELECTORS = [
    "a.mycourses_coursename",
    "a[href*='course/view.php']",
    ".coursebox a[href*='course/view.php']",
    "[data-courseurl] a",
    "div.course_title a",
]

_GUEST_XPATH = "//*[contains(., 'גישת אורחים')]"


def _is_maintenance_page(driver: webdriver.Chrome) -> bool:
    """Return True if the current page appears to be a Moodle maintenance page.

    The actual page title uses the misspelling "Maintenence", so we match on
    the common prefix "mainten" to catch all spelling variants.
    """
    title = (driver.title or "").lower()
    return "mainten" in title


def _courses_detected(d) -> bool:
    """Return True if any course-list element or guest-access indicator is found."""
    for sel in _COURSE_CSS_SELECTORS:
        if d.find_elements(By.CSS_SELECTOR, sel):
            return True
    if d.find_elements(By.XPATH, _GUEST_XPATH):
        return True
    return False


def ensure_logged_in_moodle(driver: webdriver.Chrome) -> None:
    """
    Go to MyCourses.
    If guest access -> click login -> complete SSO -> back to MyCourses.
    Retries with a page refresh if the first wait times out.
    Raises MoodleMaintenanceError if Moodle is under maintenance.
    """
    wait = WebDriverWait(driver, WAIT_SEC)
    logger.info("Navigating to MyCourses: %s", MY_COURSES_URL)
    driver.get(MY_COURSES_URL)
    wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
    time.sleep(1.5)

    if _is_maintenance_page(driver):
        # MY_COURSES_URL shows a maintenance page – verify whether this is a
        # URL-specific issue (plugin down) or genuine site-wide maintenance by
        # checking the main dashboard before giving up.
        logger.warning(
            "Maintenance page on MyCourses (url=%s, title=%r) – "
            "verifying via dashboard %s",
            driver.current_url, driver.title, MOODLE_DASHBOARD_URL,
        )
        driver.get(MOODLE_DASHBOARD_URL)
        wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        time.sleep(1.5)
        if _is_maintenance_page(driver):
            raise MoodleMaintenanceError(
                f"maintenance page detected on url={driver.current_url!r}, title={driver.title!r}"
            )
        logger.info(
            "Dashboard accessible (url=%s) – "
            "MyCourses plugin unavailable but Moodle is up; continuing from dashboard",
            driver.current_url,
        )

    if click_login_if_guest(driver):
        logger.info("Guest access detected – clicking login link")
        time.sleep(2)

        if "nidp.tau.ac.il" in driver.current_url.lower():
            logger.info("Redirected to NIDP – filling SSO form")
            maybe_login_nidp(driver)
            ensure_on_moodle(driver)

        logger.info("Returning to MyCourses after SSO")
        driver.get(MY_COURSES_URL)
        wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))

        if _is_maintenance_page(driver):
            raise MoodleMaintenanceError(
                f"maintenance page detected (url={driver.current_url!r}, title={driver.title!r})"
            )

    try:
        wait.until(_courses_detected)
        logger.info("Course list detected on first attempt")
    except TimeoutException:
        if _is_maintenance_page(driver):
            raise MoodleMaintenanceError(
                f"maintenance page detected (url={driver.current_url!r}, title={driver.title!r})"
            )
        logger.warning(
            "Timeout waiting for courses (url=%s) – refreshing page and retrying",
            driver.current_url,
        )
        driver.refresh()
        wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        time.sleep(1.5)
        if _is_maintenance_page(driver):
            raise MoodleMaintenanceError(
                f"maintenance page detected (url={driver.current_url!r}, title={driver.title!r})"
            )
        try:
            wait.until(_courses_detected)
            logger.info("Course list detected after page refresh")
        except TimeoutException:
            logger.error(
                "Still no course list after refresh. Page title: %s | URL: %s",
                driver.title,
                driver.current_url,
            )
            raise

    if driver.find_elements(By.XPATH, _GUEST_XPATH):
        raise RuntimeError("Still guest access on MyCourses; SSO did not complete automatically.")


def get_courses(driver: webdriver.Chrome) -> list[tuple[str, str]]:
    ensure_logged_in_moodle(driver)

    wait = WebDriverWait(driver, WAIT_SEC)

    # Try the primary selector first; fall back to any course link if not found
    try:
        wait.until(EC.presence_of_all_elements_located((By.CSS_SELECTOR, "a.mycourses_coursename")))
        links = driver.find_elements(By.CSS_SELECTOR, "a.mycourses_coursename")
        logger.info("Found %d elements via primary selector 'a.mycourses_coursename'", len(links))
    except TimeoutException:
        logger.warning(
            "Primary course selector timed out – falling back to generic course link selector"
        )
        links = driver.find_elements(By.CSS_SELECTOR, "a[href*='course/view.php']")
        logger.info("Found %d elements via fallback selector 'a[href*=course/view.php]'", len(links))

    courses: list[tuple[str, str]] = []
    for a in links:
        name = (a.text or "").strip()
        href = a.get_attribute("href")
        if name and href and "course/view.php?id=" in href:
            courses.append((name, href))

    if not courses:
        logger.warning(
            "No courses found on MyCourses page (url=%s, title=%s). "
            "The page structure may have changed.",
            driver.current_url,
            driver.title,
        )

    uniq: list[tuple[str, str]] = []
    seen = set()
    for n, u in courses:
        if u not in seen:
            uniq.append((n, u))
            seen.add(u)
    logger.info("Returning %d unique courses", len(uniq))
    return uniq


# ==========================
# MAIN SCAN LOGIC
# ==========================

def scan_all(session: requests.Session, courses: list[tuple[str, str]], reference_dt: datetime) -> list[FoundFile]:
    found: list[FoundFile] = []
    seen_files: set[tuple[str, str]] = set()

    for course_name_raw, course_url in courses:
        course_name_display = _course_display_name(course_name_raw)

        html = _http_get_html(session, course_url)
        if not html:
            continue

        pluginfiles, activity_pages = _extract_activity_links_from_course_html(html)

        for pf in sorted(pluginfiles):
            key = (course_url, pf)
            if key in seen_files:
                continue
            seen_files.add(key)

            lm = _get_last_modified_for_file(session, pf)
            if not lm:
                continue

            if lm > reference_dt:
                fname = _safe_filename_from_url(pf)
                found.append(FoundFile(course_name_raw, course_name_display, fname, lm, pf))

        for act in sorted(activity_pages):
            if "mod/resource/view.php" in act:
                pf_urls = _resolve_resource_view_to_file(session, act)
                for pf in pf_urls:
                    key = (course_url, pf)
                    if key in seen_files:
                        continue
                    seen_files.add(key)

                    lm = _get_last_modified_for_file(session, pf)
                    if not lm:
                        continue

                    if lm > reference_dt:
                        fname = _safe_filename_from_url(pf)
                        link_for_print = _normalize_link_for_print(act, pf)
                        found.append(FoundFile(course_name_raw, course_name_display, fname, lm, link_for_print))
            else:
                act_html = _http_get_html(session, act)
                if not act_html:
                    continue

                for pf, txt in _extract_pluginfile_links_from_html(act_html):
                    if "pluginfile.php" not in pf:
                        continue

                    key = (course_url, pf)
                    if key in seen_files:
                        continue
                    seen_files.add(key)

                    lm = _get_last_modified_for_file(session, pf)
                    if not lm:
                        continue

                    if lm > reference_dt:
                        fname = (txt.strip() or _safe_filename_from_url(pf))
                        link_for_print = _normalize_link_for_print(act, pf)
                        found.append(FoundFile(course_name_raw, course_name_display, fname, lm, link_for_print))

    found.sort(key=lambda x: (x.course_name_display, x.last_modified_il, x.file_name.lower()))
    return found


# ==========================
# ENTRY
# ==========================

def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    # validate required secrets
    if not USERNAME or not USER_ID or not PASSWORD:
        raise SystemExit("Missing Moodle secrets: MOODLE_USERNAME / MOODLE_USER_ID / MOODLE_PASSWORD")

    run_start = datetime.now(TZ_IL)
    last_run = load_last_run()

    # ── Attempt 0: Reuse saved session cookies (fastest – no login round-trip) ──
    logger.info("Trying to reuse saved Moodle session cookies…")
    http_session = load_http_session_from_cookies()

    if http_session is None:
        # ── Attempt 1: HTTP-based SAML login (no Selenium; avoids headless-Chrome bot detection) ──
        logger.info("Attempting HTTP-based SAML login (no browser)…")
        http_session = _http_saml_login()
        if http_session is not None:
            save_http_session_cookies(http_session)

    if http_session is not None:
        courses = _get_courses_via_http(http_session)
        if courses:
            logger.info("HTTP mode: found %d courses – running scan", len(courses))
            print(f"\nFound {len(courses)} courses (HTTP mode).\n")
            results = scan_all(http_session, courses, last_run)
            save_last_run(run_start)
            if not results:
                print("No updates since last run. (No Telegram message will be sent.)")
                return
            lines = [_format_line(x) for x in results]
            header = f"📌 עדכונים במודל מאז {last_run.strftime('%d.%m.%Y %H:%M')} ({len(lines)}):"
            telegram_send_many(lines, header)
            return
        logger.warning("HTTP mode: login succeeded but no courses found – falling back to Selenium")

    # ── Attempt 2: Fall back to Selenium browser login ──
    logger.info("Falling back to Selenium browser login…")
    driver = build_driver()
    try:
        driver.get(LOGIN_URL)

        # if we see NIDP form -> fill; otherwise might already be logged in
        maybe_login_nidp(driver)
        ensure_on_moodle(driver)

        courses = get_courses(driver)
        print(f"\nFound {len(courses)} courses.\n")

        session = _session_from_selenium_cookies(driver)
        # Cache cookies so the next run can skip Selenium entirely
        save_http_session_cookies(session)
        results = scan_all(session, courses, last_run)

        # Update state even if no results (so next run checks only since now)
        save_last_run(run_start)

        if not results:
            print("No updates since last run. (No Telegram message will be sent.)")
            return

        lines = [_format_line(x) for x in results]
        header = f"📌 עדכונים במודל מאז {last_run.strftime('%d.%m.%Y %H:%M')} ({len(lines)}):"
        telegram_send_many(lines, header)

    finally:
        try:
            driver.quit()
        except Exception:
            pass


if __name__ == "__main__":
    for attempt in range(1, MAINTENANCE_RETRY_COUNT + 2):  # attempts: 1 … MAINTENANCE_RETRY_COUNT+1
        try:
            main()
            break  # success – exit retry loop
        except MoodleMaintenanceError as e:
            if attempt <= MAINTENANCE_RETRY_COUNT:
                logger.warning(
                    "Maintenance page on attempt %d/%d – retrying in %ds. (%s)",
                    attempt, MAINTENANCE_RETRY_COUNT + 1, MAINTENANCE_RETRY_DELAY_SEC, e,
                )
                time.sleep(MAINTENANCE_RETRY_DELAY_SEC)
                continue

            # All retries exhausted – log and notify once (subject to throttle).
            logger.warning(
                "Moodle maintenance confirmed after %d attempt(s) – skipping this run. (%s)",
                attempt, e,
            )
            # For manual (workflow_dispatch) runs: always notify so the user gets immediate feedback.
            # For scheduled runs: throttle to at most once per MAINTENANCE_NOTIFY_THROTTLE_HOURS hours
            # to avoid spamming during prolonged maintenance windows.
            now = datetime.now(TZ_IL)
            last_notified = load_last_maintenance_notified()
            throttle_sec = MAINTENANCE_NOTIFY_THROTTLE_HOURS * 3600
            is_manual = GITHUB_EVENT_NAME == "workflow_dispatch"
            if is_manual or last_notified is None or (now - last_notified).total_seconds() >= throttle_sec:
                last_run = load_last_run()
                maint_msg = (
                    f"⚠️ מודל בתחזוקה – סריקה דולגה\n"
                    f"פרטים: {e}\n"
                    f"הסריקה הבאה תבדוק קבצים מאז "
                    f"{last_run.strftime('%d.%m.%Y %H:%M')}"
                )
                telegram_send(maint_msg)
                save_maintenance_notified(now)
        except Exception as e:
            # send error to Telegram (very important)
            run_link = github_run_url()
            tb = traceback.format_exc()

            msg = "❌ Moodle scan failed (Exception)\n"
            if run_link:
                msg += f"🔗 Logs: {run_link}\n\n"
            msg += tb

            # Telegram has length limits; clip a bit
            if len(msg) > 3800:
                msg = msg[:3800] + "\n...\n(Traceback clipped)"

            telegram_send(msg)
            raise
