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
from urllib.parse import unquote, urlparse
import json
import base64
import os
import re
import time
import traceback
import random

import requests
from selenium import webdriver
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


# ==========================
# CONFIG
# ==========================

LOGIN_URL = "https://nidp.tau.ac.il/nidp/saml2/sso?id=10&sid=0&option=credential&sid=0"
MY_COURSES_URL = "https://moodle.tau.ac.il/local/mycourses/"
MOODLE_SAML_LOGIN_URL = "https://moodle.tau.ac.il/auth/saml2/login.php"

TZ_IL = ZoneInfo("Asia/Jerusalem")
WAIT_SEC = 30
HEADLESS = os.environ.get("MOODLE_HEADLESS", "true").strip().lower() in ("1", "true", "yes", "on")

STATE_FILE = "last_run.json"  # will be created/updated in repo
LOGIN_DEBUG_HTML = "login_debug_page.html"


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

MOODLE_COOKIE_SEED_B64 = os.environ.get("MOODLE_COOKIE_SEED_B64", "")
MOODLE_COOKIE_SEED_FILE = os.environ.get("MOODLE_COOKIE_SEED_FILE", "")

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


def _load_cookie_seed() -> list[dict]:
    """Load cookies exported locally (JSON list) from file or base64 env."""
    raw = ""
    if MOODLE_COOKIE_SEED_FILE:
        try:
            with open(MOODLE_COOKIE_SEED_FILE, "r", encoding="utf-8") as f:
                raw = f.read()
        except Exception as e:
            print(f"[cookie-seed] failed reading file: {e}")
    elif MOODLE_COOKIE_SEED_B64:
        try:
            raw = base64.b64decode(MOODLE_COOKIE_SEED_B64).decode("utf-8")
        except Exception as e:
            print(f"[cookie-seed] failed decoding base64: {e}")

    if not raw:
        return []

    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict) and x.get("name") and x.get("value")]
    except Exception as e:
        print(f"[cookie-seed] invalid json: {e}")
    return []


def _inject_cookie_seed(driver: webdriver.Chrome, cookies: list[dict]) -> None:
    if not cookies:
        return

    moodle_cookies = []
    nidp_cookies = []
    for c in cookies:
        d = (c.get("domain") or "").lower()
        if "nidp.tau.ac.il" in d:
            nidp_cookies.append(c)
        else:
            moodle_cookies.append(c)

    # domain must be open before add_cookie
    if moodle_cookies:
        driver.get("https://moodle.tau.ac.il/")
        for c in moodle_cookies:
            try:
                driver.add_cookie(c)
            except Exception:
                pass

    if nidp_cookies:
        driver.get("https://nidp.tau.ac.il/")
        for c in nidp_cookies:
            try:
                driver.add_cookie(c)
            except Exception:
                pass

    print(f"[cookie-seed] injected {len(moodle_cookies)} moodle + {len(nidp_cookies)} nidp cookies")


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


def _extract_course_links_from_html(html: str) -> list[tuple[str, str]]:
    """Parse course links from any Moodle page HTML variant."""
    soup = BeautifulSoup(html, "html.parser")
    out: list[tuple[str, str]] = []
    for a in soup.select("a[href*='course/view.php?id=']"):
        href = (a.get("href") or "").strip()
        if not href:
            continue
        text = (a.get_text(" ", strip=True) or "").strip()
        if not text:
            text = href
        out.append((text, href))
    return out


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

def load_last_run() -> datetime:
    # default: last hour (so first run won't spam months)
    fallback = datetime.now(TZ_IL) - timedelta(hours=1)

    if not os.path.exists(STATE_FILE):
        return fallback

    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        iso = data.get("last_run_iso")
        if not iso:
            return fallback
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=TZ_IL)
        return dt.astimezone(TZ_IL)
    except Exception:
        return fallback


def save_last_run(run_start: datetime) -> None:
    data = {"last_run_iso": run_start.astimezone(TZ_IL).isoformat()}
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


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



def _human_delay(base: float = 0.5, jitter: float = 0.8) -> None:
    try:
        time.sleep(base + random.random() * jitter)
    except Exception:
        time.sleep(base)

def build_driver() -> webdriver.Chrome:
    options = Options()
    options.add_argument("--disable-notifications")
    options.add_argument("--disable-popup-blocking")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1365,920")
    options.add_argument("--lang=he-IL")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)

    if HEADLESS:
        options.add_argument("--headless=new")

    driver = webdriver.Chrome(options=options)
    try:
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
            "source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
        })
    except Exception:
        pass
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


def _recover_from_nidp_portal(driver: webdriver.Chrome) -> None:
    """When stuck on Access Manager portal, force Moodle-side SAML callback."""
    cur = (driver.current_url or "").lower()
    if "nidp.tau.ac.il/nidp/portal" not in cur:
        return
    print("[login] on NIDP portal; forcing Moodle SAML login endpoint")
    driver.get(MOODLE_SAML_LOGIN_URL)


def click_login_if_guest(driver: webdriver.Chrome) -> bool:
    selectors = [
        "#usernavigation a[href*='/login/index.php']",
        "a[href='https://moodle.tau.ac.il/login/index.php']",
        "a[href*='moodle.tau.ac.il/login/index.php']",
        "a[href*='/login/index.php']",
        "a[href*='nidp.tau.ac.il']",
        "button[data-action='login']",
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

    try:
        els = driver.find_elements(
            By.XPATH,
            "//a[contains(normalize-space(.), 'כניסה') or contains(normalize-space(.), 'Login') or contains(normalize-space(.), 'Sign in')]",
        )
        for el in els:
            if el.is_displayed():
                driver.execute_script("arguments[0].click();", el)
                return True
    except Exception:
        pass

    return False


def _is_guest_page(driver: webdriver.Chrome) -> bool:
    guest_indicators = [
        "//*[contains(., 'גישת אורחים')]",
        "//*[contains(., 'Guest access')]",
        "//*[contains(., 'You are currently using guest access')]",
    ]
    for xp in guest_indicators:
        try:
            if driver.find_elements(By.XPATH, xp):
                return True
        except Exception:
            continue
    return False


def _has_login_link(driver: webdriver.Chrome) -> bool:
    checks = [
        "//a[contains(@href, '/login/index.php')]",
        "//a[contains(@href, 'nidp.tau.ac.il')]",
        "//button[@data-action='login']",
    ]
    for xp in checks:
        try:
            if driver.find_elements(By.XPATH, xp):
                return True
        except Exception:
            continue
    return False


def _is_maintenance_or_denied_page(driver: webdriver.Chrome) -> bool:
    """Detect TAU/WAF maintenance or access-denied splash pages."""
    title = (driver.title or "").lower()
    html = (driver.page_source or "").lower()
    markers = [
        "under maintenence",
        "under maintenance",
        "access denied",
        "your support id is",
        "בקשה נדחתה",
    ]
    if any(m in title for m in markers):
        return True
    if any(m in html for m in markers):
        return True
    return False


def _find_course_links(driver: webdriver.Chrome):
    """Support multiple MyCourses DOM variants (class names changed over time)."""
    selectors = [
        "a.mycourses_coursename",
        "a.coursename",
        "a[href*='/course/view.php?id=']",
    ]
    links = []
    for sel in selectors:
        try:
            links = driver.find_elements(By.CSS_SELECTOR, sel)
        except Exception:
            links = []
        if links:
            break
    return links


def _unique_courses(courses: list[tuple[str, str]]) -> list[tuple[str, str]]:
    uniq: list[tuple[str, str]] = []
    seen = set()
    for n, u in courses:
        if not u or "course/view.php?id=" not in u:
            continue
        if u in seen:
            continue
        uniq.append((n.strip() or u, u))
        seen.add(u)
    return uniq


def _courses_from_current_dom(driver: webdriver.Chrome) -> list[tuple[str, str]]:
    courses: list[tuple[str, str]] = []
    for a in _find_course_links(driver):
        try:
            name = (a.text or "").strip()
            href = a.get_attribute("href")
            courses.append((name, href))
        except Exception:
            continue
    return _unique_courses(courses)


def ensure_logged_in_moodle(driver: webdriver.Chrome) -> None:
    """
    Go to MyCourses.
    If guest access or an intermediate page appears, force SSO and retry.
    """
    wait = WebDriverWait(driver, WAIT_SEC)
    last_state = "unknown"

    for attempt in range(1, 5):
        driver.get(MY_COURSES_URL)
        wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        _human_delay(0.8, 0.7)

        # Fast success path
        if _find_course_links(driver):
            return

        # Try clicking login affordances if they exist
        if click_login_if_guest(driver):
            print(f"[login] attempt {attempt}: clicked login link/button")
            _human_delay(1.0, 1.0)

        # If redirected to NIDP, submit SSO form
        if "nidp.tau.ac.il" in driver.current_url.lower():
            _recover_from_nidp_portal(driver)
            print(f"[login] attempt {attempt}: on NIDP, trying form fill")
            maybe_login_nidp(driver)
            ensure_on_moodle(driver)
            driver.get(MY_COURSES_URL)
            wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))

        # Success after click/redirect handling
        if _find_course_links(driver):
            return

        # Hard fallback: force-open SSO entry URL and return to MyCourses
        print(f"[login] attempt {attempt}: forcing LOGIN_URL flow")
        driver.get(LOGIN_URL)
        wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        maybe_login_nidp(driver)
        ensure_on_moodle(driver)
        driver.get(MY_COURSES_URL)
        wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))

        if _find_course_links(driver):
            return

        if _is_maintenance_or_denied_page(driver):
            last_state = "maintenance_or_denied"
            print(f"[login] attempt {attempt}: maintenance/access-denied page detected")
            continue

        if _is_guest_page(driver) or _has_login_link(driver):
            last_state = "guest_or_login"
            print(f"[login] attempt {attempt}: still guest/login page")
            continue

        last_state = "unknown_page"

    page_html = driver.page_source or ""
    try:
        with open(LOGIN_DEBUG_HTML, "w", encoding="utf-8") as f:
            f.write(page_html)
        print(f"[login] wrote debug HTML: {LOGIN_DEBUG_HTML}")
    except Exception as dump_err:
        print(f"[login] failed writing debug HTML: {dump_err}")

    page_excerpt = page_html[:4000]
    raise RuntimeError(
        "Could not reach logged-in MyCourses state after retries. "
        f"state={last_state}\n"
        f"url={driver.current_url}\n"
        f"title={driver.title}\n"
        f"page_excerpt={page_excerpt}"
    )


def _expand_mycourses_dynamic_list(driver: webdriver.Chrome) -> None:
    """Try to trigger lazy course rendering in MyCourses blocks."""
    end = time.time() + 20
    while time.time() < end:
        # click "more courses" if present
        try:
            btns = driver.find_elements(By.CSS_SELECTOR, "[data-action='more-courses']")
            clicked = False
            for b in btns:
                if b.is_displayed() and b.is_enabled():
                    driver.execute_script("arguments[0].click();", b)
                    clicked = True
                    _human_delay(0.4, 0.6)
            if clicked:
                continue
        except Exception:
            pass

        # if links appeared, we are done
        if _find_course_links(driver):
            return

        # wait a bit for async block rendering
        _human_delay(0.4, 0.8)


def get_courses(driver: webdriver.Chrome) -> list[tuple[str, str]]:
    ensure_logged_in_moodle(driver)

    # allow lazy blocks to render course anchors
    _expand_mycourses_dynamic_list(driver)

    # 1) Fast path: links in current DOM
    courses = _courses_from_current_dom(driver)
    if courses:
        return courses

    # 2) Fallback: parse current HTML directly (some themes render links outside expected selectors)
    html = driver.page_source or ""
    courses = _unique_courses(_extract_course_links_from_html(html))
    if courses:
        return courses

    # 3) Last resort: try additional Moodle entry points after successful SSO
    for url in ("https://moodle.tau.ac.il/my/", "https://moodle.tau.ac.il/my/courses.php"):
        try:
            driver.get(url)
            WebDriverWait(driver, WAIT_SEC).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            courses = _courses_from_current_dom(driver)
            if courses:
                return courses
            courses = _unique_courses(_extract_course_links_from_html(driver.page_source or ""))
            if courses:
                return courses
        except Exception:
            continue

    raise RuntimeError(f"No courses found after login. final_url={driver.current_url}")


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
    cookie_seed = _load_cookie_seed()

    # validate secrets only when no external session seed is provided
    if not cookie_seed and (not USERNAME or not USER_ID or not PASSWORD):
        raise SystemExit("Missing Moodle secrets: MOODLE_USERNAME / MOODLE_USER_ID / MOODLE_PASSWORD")

    run_start = datetime.now(TZ_IL)
    last_run = load_last_run()

    last_exc: Exception | None = None
    for attempt in range(1, 4):
        driver = build_driver()
        try:
            print(f"[main] scan attempt {attempt}/3")
            if cookie_seed:
                _inject_cookie_seed(driver, cookie_seed)

            # Prefer Moodle-side flow first (matches successful manual UX):
            # /local/mycourses/ -> click "התחבר/י" -> NIDP -> back to MyCourses.
            start_urls = [
                MY_COURSES_URL,
                "https://moodle.tau.ac.il/my/courses.php",
                "https://moodle.tau.ac.il/my/",
            ]

            start_ok = False
            for su in start_urls:
                driver.get(su)
                if _is_maintenance_or_denied_page(driver):
                    print(f"[main] start URL blocked: {su}")
                    continue
                start_ok = True
                break

            if not start_ok:
                # last resort: try direct NIDP entry once
                print("[main] all Moodle start URLs blocked; trying direct LOGIN_URL")
                driver.get(LOGIN_URL)

            # if we see NIDP form -> fill; otherwise continue with Moodle-side login checks
            if "nidp.tau.ac.il" in driver.current_url.lower():
                _recover_from_nidp_portal(driver)
                maybe_login_nidp(driver)
                ensure_on_moodle(driver)

            courses = get_courses(driver)
            print(f"\nFound {len(courses)} courses.\n")

            session = _session_from_selenium_cookies(driver)
            results = scan_all(session, courses, last_run)

            # Update state even if no results (so next run checks only since now)
            save_last_run(run_start)

            if not results:
                print("No updates since last run. (No Telegram message will be sent.)")
                return

            lines = [_format_line(x) for x in results]
            header = f"📌 עדכונים במודל מאז {last_run.strftime('%d.%m.%Y %H:%M')} ({len(lines)}):"
            telegram_send_many(lines, header)
            return

        except Exception as e:
            last_exc = e
            msg = str(e).lower()
            transient = ("maintenance" in msg) or ("access denied" in msg) or ("support id" in msg)
            if transient and attempt < 3:
                wait_sec = 45 * attempt
                print(f"[main] transient maintenance/denied detected; sleeping {wait_sec}s before retry")
                time.sleep(wait_sec)
                continue
            raise
        finally:
            try:
                driver.quit()
            except Exception:
                pass

    if last_exc:
        raise last_exc


if __name__ == "__main__":
    try:
        main()
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
