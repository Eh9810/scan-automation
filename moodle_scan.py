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
import os
import re
import time
import traceback

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

LOGIN_URL      = "https://nidp.tau.ac.il/nidp/saml2/sso?id=10&sid=0&option=credential&sid=0"
MY_COURSES_URL = "https://moodle.tau.ac.il/local/mycourses/"
MOODLE_BASE    = "https://moodle.tau.ac.il"

TZ_IL    = ZoneInfo("Asia/Jerusalem")
WAIT_SEC = 45          # increased from 30
HEADLESS = True

STATE_FILE = "last_run.json"

# ==========================
# SECRETS (from GitHub Actions env vars)
# ==========================
USERNAME = os.environ.get("MOODLE_USERNAME", "")
USER_ID  = os.environ.get("MOODLE_USER_ID", "")
PASSWORD = os.environ.get("MOODLE_PASSWORD", "")

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "")


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
    s = (raw or "").strip()
    if " - " in s:
        left, right = s.split(" - ", 1)
        # Strip leading zeros before checking if it's a course code
        if re.fullmatch(r"0*\d{6,}", left.strip()):
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
    pluginfiles    = set()
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
        joiner   = "&" if "?" in view_url else "?"
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
        f"{item.course_name_display} | "
        f"שם הקובץ: {item.file_name} | "
        f"שינוי אחרון: {item.last_modified_il.strftime('%d.%m.%Y %H:%M')} | "
        f"קישור: {item.link}"
    )


# ==========================
# STATE (last run)
# ==========================

def load_last_run() -> datetime:
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
    url     = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "disable_web_page_preview": True,
    }
    try:
        r = requests.post(url, json=payload, timeout=30)
        print(r.text)
    except Exception as e:
        print(f"Telegram send failed: {e}")


def telegram_send_many(lines: list[str], header: str) -> None:
    max_len = 3800
    chunk   = header + "\n"
    for line in lines:
        if len(chunk) + len(line) + 1 > max_len:
            telegram_send(chunk)
            chunk = header + "\n"
        chunk += line + "\n"
    if chunk.strip():
        telegram_send(chunk)


def github_run_url() -> str:
    repo   = os.environ.get("GITHUB_REPOSITORY", "")
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
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    if HEADLESS:
        options.add_argument("--headless=new")
    return webdriver.Chrome(options=options)


def _find_any(driver: webdriver.Chrome, by: By, values: list[str]):
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
    Fill NIDP login form if present on the current page.
    Tries multiple known field IDs used by TAU NIDP.
    """
    wait = WebDriverWait(driver, WAIT_SEC)

    user_ids = ["Ecom_User_ID", "Ecom_UserID", "Ecom_Username", "username", "user"]
    pid_ids  = ["Ecom_Taz", "Ecom_User_Pid", "Ecom_Pid", "pid", "tz"]
    pass_ids = ["Ecom_Password", "Ecom_Pass", "password", "pass"]

    def any_visible_login_field_present(d):
        return (_find_any(d, By.ID, user_ids) is not None) or \
               (_find_any(d, By.ID, pass_ids) is not None)

    try:
        wait.until(any_visible_login_field_present)
    except Exception:
        print("  No login form detected — skipping NIDP fill.")
        return

    def _safe_fill(el, value: str):
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
        try:
            el.send_keys(Keys.CONTROL, "a")
            el.send_keys(Keys.BACKSPACE)
            el.send_keys(value)
            return
        except Exception:
            driver.execute_script(
                "arguments[0].value = arguments[1];"
                "arguments[0].dispatchEvent(new Event('input', {bubbles:true}));"
                "arguments[0].dispatchEvent(new Event('change', {bubbles:true}));",
                el, value,
            )

    user_field = _find_any(driver, By.ID, user_ids)
    if user_field:
        _safe_fill(user_field, USERNAME)

    pid_field = _find_any(driver, By.ID, pid_ids)
    if pid_field:
        _safe_fill(pid_field, USER_ID)

    pass_field = _find_any(driver, By.ID, pass_ids)
    if not pass_field:
        print("  WARNING: password field not found on NIDP page!")
        return

    _safe_fill(pass_field, PASSWORD)
    pass_field.send_keys(Keys.RETURN)
    print("  Submitted NIDP login form.")


def ensure_on_moodle(driver: webdriver.Chrome) -> None:
    """Wait until we land on moodle.tau.ac.il (handle NIDP portal redirect)."""
    wait = WebDriverWait(driver, WAIT_SEC)

    def reached_moodle_or_portal(d):
        url = d.current_url.lower()
        return ("moodle.tau.ac.il" in url) or ("nidp.tau.ac.il/nidp/portal" in url)

    try:
        wait.until(reached_moodle_or_portal)
    except Exception:
        print(f"  WARNING: still on {driver.current_url} after waiting.")

    if "nidp.tau.ac.il/nidp/portal" in driver.current_url.lower():
        print("  Landed on NIDP portal — navigating to Moodle MyCourses...")
        driver.get(MY_COURSES_URL)

    try:
        wait.until(lambda d: "moodle.tau.ac.il" in d.current_url.lower())
    except Exception:
        raise RuntimeError(f"Could not reach moodle.tau.ac.il; stuck at: {driver.current_url}")

    print(f"  On Moodle: {driver.current_url}")


def _is_logged_in(driver: webdriver.Chrome) -> bool:
    """
    Return True if the current page shows a logged-in user.
    We check for absence of 'התחבר' link and presence of user menu or user initials.
    """
    # If there's a visible login link, we're NOT logged in
    try:
        login_links = driver.find_elements(
            By.XPATH,
            "//a[contains(@href, '/login/index.php') and not(contains(@class,'sr-only'))]"
        )
        for a in login_links:
            if a.is_displayed():
                return False
    except Exception:
        pass

    # If we can find the user menu toggle, we ARE logged in
    try:
        el = driver.find_element(By.CSS_SELECTOR, "#user-menu-toggle, .userinitials")
        if el.is_displayed():
            return True
    except Exception:
        pass

    # Check for "גישת אורחים" text
    try:
        body = driver.find_element(By.TAG_NAME, "body").text
        if "גישת אורחים" in body:
            return False
    except Exception:
        pass

    return True  # assume logged in if nothing contradicts


def _wait_for_page_ready(driver: webdriver.Chrome, timeout: int = 30) -> None:
    """Wait for document.readyState == 'complete'."""
    WebDriverWait(driver, timeout).until(
        lambda d: d.execute_script("return document.readyState") == "complete"
    )


def ensure_logged_in_moodle(driver: webdriver.Chrome) -> None:
    """
    Navigate to MY_COURSES_URL and make sure we are authenticated.
    If not logged in, trigger SSO flow and come back.
    """
    wait = WebDriverWait(driver, WAIT_SEC)

    driver.get(MY_COURSES_URL)
    _wait_for_page_ready(driver)
    time.sleep(2)

    print(f"  Current URL after get(MY_COURSES_URL): {driver.current_url}")

    # If we ended up on NIDP (session expired / not logged in), do SSO
    if "nidp.tau.ac.il" in driver.current_url.lower():
        print("  Redirected to NIDP — logging in...")
        maybe_login_nidp(driver)
        ensure_on_moodle(driver)
        _wait_for_page_ready(driver)
        time.sleep(2)
        # Navigate back to MY_COURSES_URL after SSO
        driver.get(MY_COURSES_URL)
        _wait_for_page_ready(driver)
        time.sleep(2)

    # If still showing guest / login link on Moodle page
    if not _is_logged_in(driver):
        print("  Not logged in on Moodle — clicking login link...")
        # Try clicking any visible login link
        try:
            login_els = driver.find_elements(
                By.XPATH,
                "//a[contains(@href, '/login/index.php') and not(contains(@class,'sr-only'))]"
            )
            for a in login_els:
                if a.is_displayed():
                    driver.execute_script("arguments[0].click();", a)
                    break
        except Exception:
            pass

        time.sleep(2)

        if "nidp.tau.ac.il" in driver.current_url.lower():
            maybe_login_nidp(driver)
            ensure_on_moodle(driver)
            _wait_for_page_ready(driver)
            time.sleep(2)

        driver.get(MY_COURSES_URL)
        _wait_for_page_ready(driver)
        time.sleep(2)

    if not _is_logged_in(driver):
        raise RuntimeError(
            f"Still not logged in to Moodle after SSO attempts. URL: {driver.current_url}"
        )

    print("  Confirmed logged in to Moodle.")


# ==========================
# GET COURSES
# ==========================

def _get_courses_from_calendar_select(driver: webdriver.Chrome) -> list[tuple[str, str]]:
    """
    Parse courses from the calendar course-filter <select>.
    This element is in the static HTML (server-rendered), so it should be
    available immediately after page load — no JS required.

    The option values are course IDs (e.g. '509182907') and the text is the
    full course name (e.g. '0509182907 - פיזיקה (2)').
    """
    courses = []
    try:
        # Wait up to 15 s for the calendar select to appear
        WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "select.cal_courses_flt"))
        )
        opts = driver.find_elements(By.CSS_SELECTOR, "select.cal_courses_flt option")
        print(f"  Found {len(opts)} <option> elements in calendar select.")
        for opt in opts:
            value = (opt.get_attribute("value") or "").strip()
            name  = (opt.text or "").strip()
            # Skip "all courses" sentinel (value == "1") and blanks
            if not value or value == "1" or not name:
                continue
            course_url = f"{MOODLE_BASE}/course/view.php?id={value}"
            courses.append((name, course_url))
            print(f"    course: {name!r} -> {course_url}")
    except Exception as e:
        print(f"  Warning: could not read calendar select: {e}")
    return courses


def _get_courses_from_page_source(driver: webdriver.Chrome) -> list[tuple[str, str]]:
    """
    Fallback: parse the raw page source with BeautifulSoup to find
    select.cal_courses_flt options (avoids Selenium stale-element issues).
    """
    courses = []
    try:
        soup = BeautifulSoup(driver.page_source, "html.parser")
        sel  = soup.select_one("select.cal_courses_flt")
        if not sel:
            print("  Fallback BS4: <select class='cal_courses_flt'> NOT found in page source.")
            return courses
        opts = sel.find_all("option")
        print(f"  Fallback BS4: found {len(opts)} <option> in calendar select.")
        for opt in opts:
            value = (opt.get("value") or "").strip()
            name  = (opt.get_text() or "").strip()
            if not value or value == "1" or not name:
                continue
            course_url = f"{MOODLE_BASE}/course/view.php?id={value}"
            courses.append((name, course_url))
    except Exception as e:
        print(f"  Warning in fallback BS4 parse: {e}")
    return courses


def _get_courses_from_dynamic_links(driver: webdriver.Chrome) -> list[tuple[str, str]]:
    """
    Last-resort: wait for JS-rendered course links.
    Tries multiple CSS selectors that may match course links.
    """
    wait = WebDriverWait(driver, WAIT_SEC)
    selectors = [
        "a.mycourses_coursename",
        "#block-mycourses a[href*='course/view.php?id=']",
        ".block-mycourses a[href*='course/view.php?id=']",
        "a[href*='course/view.php?id=']",
    ]
    for sel in selectors:
        try:
            wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, sel)))
            links = driver.find_elements(By.CSS_SELECTOR, sel)
            courses = []
            seen    = set()
            for a in links:
                name = (a.text or "").strip()
                href = (a.get_attribute("href") or "").strip()
                if not name or not href or "course/view.php?id=" not in href:
                    continue
                if href in seen:
                    continue
                seen.add(href)
                courses.append((name, href))
            if courses:
                print(f"  Dynamic links via '{sel}': found {len(courses)} courses.")
                return courses
        except Exception:
            continue
    return []


def get_courses(driver: webdriver.Chrome) -> list[tuple[str, str]]:
    ensure_logged_in_moodle(driver)

    # Give the page extra time to fully render the static HTML
    time.sleep(3)

    # --- Strategy 1: Selenium read of calendar <select> ---
    courses = _get_courses_from_calendar_select(driver)

    # --- Strategy 2: BeautifulSoup on raw page_source ---
    if not courses:
        print("  Calendar select via Selenium empty — trying BS4 on page source...")
        courses = _get_courses_from_page_source(driver)

    # --- Strategy 3: wait for JS-rendered course card links ---
    if not courses:
        print("  BS4 also empty — waiting for dynamic JS course links...")
        courses = _get_courses_from_dynamic_links(driver)

    # Deduplicate by URL
    seen = set()
    uniq = []
    for n, u in courses:
        if u not in seen:
            uniq.append((n, u))
            seen.add(u)

    print(f"  Total unique courses: {len(uniq)}")
    return uniq


# ==========================
# MAIN SCAN LOGIC
# ==========================

def scan_all(
    session: requests.Session,
    courses: list[tuple[str, str]],
    reference_dt: datetime,
) -> list[FoundFile]:
    found: list[FoundFile] = []
    seen_files: set[tuple[str, str]] = set()

    for course_name_raw, course_url in courses:
        course_name_display = _course_display_name(course_name_raw)
        print(f"  Scanning: {course_name_display} ({course_url})")

        html = _http_get_html(session, course_url)
        if not html:
            print(f"    -> Could not fetch HTML for {course_url}")
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
                        fname          = _safe_filename_from_url(pf)
                        link_for_print = _normalize_link_for_print(act, pf)
                        found.append(FoundFile(
                            course_name_raw, course_name_display, fname, lm, link_for_print
                        ))
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
                        fname          = (txt.strip() or _safe_filename_from_url(pf))
                        link_for_print = _normalize_link_for_print(act, pf)
                        found.append(FoundFile(
                            course_name_raw, course_name_display, fname, lm, link_for_print
                        ))

    found.sort(key=lambda x: (x.course_name_display, x.last_modified_il, x.file_name.lower()))
    return found


# ==========================
# ENTRY
# ==========================

def main():
    if not USERNAME or not USER_ID or not PASSWORD:
        raise SystemExit(
            "Missing Moodle secrets: MOODLE_USERNAME / MOODLE_USER_ID / MOODLE_PASSWORD"
        )

    run_start = datetime.now(TZ_IL)
    last_run  = load_last_run()
    print(f"Last run: {last_run.strftime('%d.%m.%Y %H:%M %Z')}")

    driver = build_driver()
    try:
        # -------------------------------------------------------
        # Step 1: Go directly to MY_COURSES_URL.
        # If session is still valid from a previous run (cached cookies),
        # we land straight on Moodle. If not, Moodle will redirect us to
        # NIDP SSO, ensure_logged_in_moodle handles the full flow.
        # -------------------------------------------------------
        print("Navigating to MY_COURSES_URL to start login flow...")
        driver.get(MY_COURSES_URL)
        _wait_for_page_ready(driver)
        time.sleep(2)

        current = driver.current_url.lower()
        print(f"After initial get, URL: {driver.current_url}")

        if "nidp.tau.ac.il" in current:
            # Redirected to NIDP SSO — fill login form
            print("Redirected to NIDP — filling login form...")
            maybe_login_nidp(driver)
            ensure_on_moodle(driver)
            _wait_for_page_ready(driver)
            time.sleep(2)
            # Navigate to MY_COURSES_URL now that we're authenticated
            driver.get(MY_COURSES_URL)
            _wait_for_page_ready(driver)
            time.sleep(3)
        elif "moodle.tau.ac.il" not in current:
            # Unexpected URL — try the explicit NIDP LOGIN_URL as fallback
            print(f"Unexpected URL {driver.current_url} — trying explicit NIDP login URL...")
            driver.get(LOGIN_URL)
            _wait_for_page_ready(driver)
            maybe_login_nidp(driver)
            ensure_on_moodle(driver)
            _wait_for_page_ready(driver)
            time.sleep(2)
            driver.get(MY_COURSES_URL)
            _wait_for_page_ready(driver)
            time.sleep(3)

        # -------------------------------------------------------
        # Step 2: Verify login and get course list.
        # get_courses() internally calls ensure_logged_in_moodle() as
        # a safety net, then reads the calendar <select>.
        # -------------------------------------------------------
        courses = get_courses(driver)
        print(f"\nFound {len(courses)} courses.\n")

        if not courses:
            raise RuntimeError(
                "No courses found after login. "
                "The calendar <select> was empty and no dynamic links were found. "
                "Check that login succeeded and that the page rendered correctly."
            )

        # -------------------------------------------------------
        # Step 3: Borrow Moodle session cookies for HTTP requests
        # -------------------------------------------------------
        session = _session_from_selenium_cookies(driver)

        # -------------------------------------------------------
        # Step 4: Scan all courses for new/updated files
        # -------------------------------------------------------
        results = scan_all(session, courses, last_run)

        # Save state now (after successful scan)
        save_last_run(run_start)

        if not results:
            print("No updates since last run. (No Telegram message sent.)")
            return

        lines  = [_format_line(x) for x in results]
        header = (
            f"📌 עדכונים במודל מאז "
            f"{last_run.strftime('%d.%m.%Y %H:%M')} ({len(lines)}):"
        )
        telegram_send_many(lines, header)

    finally:
        try:
            driver.quit()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        run_link = github_run_url()
        tb       = traceback.format_exc()

        msg = "❌ Moodle scan failed (Exception)\n"
        if run_link:
            msg += f"🔗 Logs: {run_link}\n\n"
        msg += tb

        if len(msg) > 3800:
            msg = msg[:3800] + "\n...\n(Traceback clipped)"

        telegram_send(msg)
        raise
