# -*- coding: utf-8 -*-
"""
TAU Moodle scanner (GitHub Actions-ready).

What this version changes:
- Uses Selenium only for TAU NIDP login / SSO.
- Avoids depending only on /local/mycourses/ HTML.
- Tries multiple Moodle landing pages after login.
- Extracts sesskey from a Moodle page and tries Moodle AJAX course APIs.
- Falls back to parsing rendered HTML course links.
- Falls back to cached course URLs if course list retrieval is temporarily blocked.
- Scans course pages for pluginfile/resource/folder/assign links.
- Uses HTTP Last-Modified as "שינוי אחרון".
- Sends Telegram only on updates or on failure.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import unquote, urlparse, urljoin
import json
import os
import re
import time
import traceback
from typing import Any

import requests
from bs4 import BeautifulSoup
from zoneinfo import ZoneInfo

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


# ==========================
# CONFIG
# ==========================

LOGIN_URL = "https://nidp.tau.ac.il/nidp/saml2/sso?id=10&sid=0&option=credential&sid=0"
MOODLE_ROOT_URL = "https://moodle.tau.ac.il/"
# DASHBOARD_URL is the main dashboard where <select class="cal_courses_flt"> lives
DASHBOARD_URL = "https://moodle.tau.ac.il/"
MY_OVERVIEW_URL = "https://moodle.tau.ac.il/my/"
MY_COURSES_CLASSIC_URL = "https://moodle.tau.ac.il/my/courses.php"
MY_COURSES_URL = "https://moodle.tau.ac.il/local/mycourses/"

MOODLE_PAGE_CANDIDATES = [
    MY_COURSES_CLASSIC_URL,
    MY_OVERVIEW_URL,
    MOODLE_ROOT_URL,
    MY_COURSES_URL,
]

TZ_IL = ZoneInfo("Asia/Jerusalem")
WAIT_SEC = 35
HEADLESS = True

STATE_FILE = "last_run.json"
COURSE_CACHE_FILE = "course_cache.json"

REQUEST_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
)

# ==========================
# SECRETS
# ==========================

USERNAME = os.environ.get("MOODLE_USERNAME", "")
USER_ID = os.environ.get("MOODLE_USER_ID", "")
PASSWORD = os.environ.get("MOODLE_PASSWORD", "")

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")


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
# BASIC HELPERS
# ==========================

def _course_display_name(raw: str) -> str:
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


def _parse_http_last_modified(headers: dict[str, str]) -> datetime | None:
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


def _normalize_url(url: str, base: str = MOODLE_ROOT_URL) -> str:
    return urljoin(base, url)


def _clean_html_text(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip()


def _looks_like_tau_block_page(html: str, title: str = "") -> bool:
    text = f"{title}\n{html}".lower()
    bad_markers = [
        "tau under maintenence",
        "tau under maintenance",
        "access denied",
        "בקשה נדחתה",
        "please try again, or contact us for support",
        "אנא נסו שוב, או צרו קשר עם מרכז התמיכה",
    ]
    return any(m.lower() in text for m in bad_markers)


def _extract_sesskey_from_html(html: str) -> str | None:
    if not html:
        return None

    patterns = [
        r'"sesskey":"([^"]+)"',
        r"'sesskey':'([^']+)'",
        r'name="sesskey"\s+value="([^"]+)"',
        r'"sessiontimeoutwarning":"\d+".*?"sesskey":"([^"]+)"',
    ]
    for pat in patterns:
        m = re.search(pat, html)
        if m:
            return m.group(1)
    return None


def _extract_course_links_from_html(html: str) -> list[tuple[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    courses: list[tuple[str, str]] = []

    for a in soup.select("a[href*='/course/view.php?id=']"):
        href = a.get("href")
        if not href:
            continue
        href = _normalize_url(href)

        name = _clean_html_text(a.get_text(" ", strip=True))
        if not name:
            h = a.select_one("h1, h2, h3, h4, h5, h6, span, div")
            if h:
                name = _clean_html_text(h.get_text(" ", strip=True))
        if not name:
            name = href

        courses.append((name, href))

    uniq: list[tuple[str, str]] = []
    seen = set()
    for name, href in courses:
        if href not in seen:
            uniq.append((name, href))
            seen.add(href)
    return uniq


def _format_line(item: FoundFile) -> str:
    return (
        f"{item.course_name_display}\t | "
        f"שם הקובץ: {item.file_name}\t | "
        f"שינוי אחרון: {item.last_modified_il.strftime('%d.%m.%Y %H:%M')}\t | "
        f"קישור: {item.link}"
    )


# ==========================
# DEBUG
# ==========================

def _debug_dump_html_text(html: str, prefix: str) -> None:
    try:
        with open(f"{prefix}.html", "w", encoding="utf-8") as f:
            f.write(html or "")
        print(f"DEBUG saved HTML to {prefix}.html")
    except Exception as e:
        print(f"DEBUG failed saving HTML ({prefix}): {e}")


def _debug_dump_page(driver: webdriver.Chrome, prefix: str) -> None:
    try:
        current_url = driver.current_url
    except Exception:
        current_url = "<unknown>"

    try:
        title = driver.title
    except Exception:
        title = "<unknown>"

    try:
        page_source = driver.page_source
    except Exception:
        page_source = "<cannot-read-page-source>"

    print(f"DEBUG {prefix} current_url: {current_url}")
    print(f"DEBUG {prefix} title: {title}")
    print(f"DEBUG {prefix} page source snippet:\n{page_source[:5000]}")

    _debug_dump_html_text(page_source, prefix)

    try:
        driver.save_screenshot(f"{prefix}.png")
        print(f"DEBUG saved screenshot to {prefix}.png")
    except Exception as e:
        print(f"DEBUG failed saving screenshot ({prefix}): {e}")


# ==========================
# STATE / CACHE
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


def load_course_cache() -> list[tuple[str, str]]:
    if not os.path.exists(COURSE_CACHE_FILE):
        return []
    try:
        with open(COURSE_CACHE_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        out: list[tuple[str, str]] = []
        for item in raw:
            if isinstance(item, dict) and item.get("url"):
                out.append((str(item.get("name") or item["url"]), str(item["url"])))
        return out
    except Exception:
        return []


def save_course_cache(courses: list[tuple[str, str]]) -> None:
    payload = [{"name": name, "url": url} for name, url in courses]
    with open(COURSE_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


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
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if repo and run_id:
        return f"https://github.com/{repo}/actions/runs/{run_id}"
    return ""


# ==========================
# REQUESTS SESSION
# ==========================

def _session_from_selenium_cookies(driver: webdriver.Chrome) -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": REQUEST_UA,
            "Accept-Language": "he,en;q=0.9",
        }
    )

    for c in driver.get_cookies():
        try:
            s.cookies.set(
                name=c.get("name"),
                value=c.get("value"),
                domain=c.get("domain"),
                path=c.get("path", "/"),
            )
        except Exception:
            pass

    return s


def _http_head_follow(session: requests.Session, url: str, referer: str | None = None) -> requests.Response | None:
    headers = {}
    if referer:
        headers["Referer"] = referer
    try:
        r = session.head(url, allow_redirects=True, timeout=30, headers=headers)
        if r.status_code in (403, 405) or (r.status_code >= 400 and "Last-Modified" not in r.headers):
            r = session.get(url, allow_redirects=True, timeout=30, stream=True, headers=headers)
        return r
    except Exception:
        return None


def _http_get_html(session: requests.Session, url: str, referer: str | None = None) -> str | None:
    headers = {}
    if referer:
        headers["Referer"] = referer
    try:
        r = session.get(url, allow_redirects=True, timeout=40, headers=headers)
        if r.status_code >= 400:
            return None
        return r.text
    except Exception:
        return None


def _ajax_call(session: requests.Session, sesskey: str, methodname: str, args: dict[str, Any], referer: str) -> Any:
    url = f"{MOODLE_ROOT_URL}lib/ajax/service.php?sesskey={sesskey}&info={methodname}"
    headers = {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": referer,
        "Origin": MOODLE_ROOT_URL.rstrip("/"),
        "Accept": "application/json, text/javascript, */*; q=0.01",
    }
    body = [{"index": 0, "methodname": methodname, "args": args}]
    r = session.post(url, headers=headers, json=body, timeout=40)
    r.raise_for_status()
    data = r.json()

    if not isinstance(data, list) or not data:
        raise RuntimeError(f"Unexpected AJAX response for {methodname}: {type(data)}")

    first = data[0]
    if isinstance(first, dict) and first.get("error"):
        raise RuntimeError(f"Moodle AJAX error in {methodname}: {first}")

    if isinstance(first, dict) and "data" in first:
        return first["data"]
    return first


# ==========================
# SELENIUM LOGIN
# ==========================

def build_driver() -> webdriver.Chrome:
    options = Options()
    options.add_argument(f"--user-agent={REQUEST_UA}")
    options.add_argument("--disable-notifications")
    options.add_argument("--disable-popup-blocking")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1600,2200")
    if HEADLESS:
        options.add_argument("--headless=new")
    return webdriver.Chrome(options=options)


def _find_any(driver: webdriver.Chrome, by: By, values: list[str]):
    for value in values:
        try:
            el = driver.find_element(by, value)
            if el.is_displayed() and el.is_enabled():
                return el
        except Exception:
            continue
    return None


def maybe_login_nidp(driver: webdriver.Chrome) -> None:
    wait = WebDriverWait(driver, WAIT_SEC)

    user_ids = ["Ecom_User_ID", "Ecom_UserID", "Ecom_Username", "username", "user"]
    pid_ids = ["Ecom_Taz", "Ecom_User_Pid", "Ecom_Pid", "pid", "tz"]
    pass_ids = ["Ecom_Password", "Ecom_Pass", "password", "pass"]

    def any_visible_login_field_present(d):
        return (_find_any(d, By.ID, user_ids) is not None) or (_find_any(d, By.ID, pass_ids) is not None)

    try:
        wait.until(any_visible_login_field_present)
    except Exception:
        return

    def _safe_fill(el, value: str) -> None:
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
        return

    _safe_fill(pass_field, PASSWORD)
    pass_field.send_keys(Keys.RETURN)


def ensure_logged_in_to_sso(driver: webdriver.Chrome) -> None:
    driver.get(LOGIN_URL)
    maybe_login_nidp(driver)

    wait = WebDriverWait(driver, WAIT_SEC)

    def no_longer_on_login_form(d):
        url = d.current_url.lower()
        if "moodle.tau.ac.il" in url:
            return True
        if "nidp.tau.ac.il" in url:
            html = d.page_source
            if "Ecom_User_ID" not in html and "Ecom_Password" not in html:
                return True
        return False

    wait.until(no_longer_on_login_form)


def _try_open_moodle_page_in_driver(driver: webdriver.Chrome, url: str) -> tuple[bool, str]:
    try:
        driver.get(url)
        WebDriverWait(driver, 20).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        time.sleep(1.2)
        title = driver.title or ""
        html = driver.page_source or ""
        blocked = _looks_like_tau_block_page(html, title)
        print(f"DEBUG tried page {url} | title={title!r} | blocked={blocked}")
        return (not blocked), html
    except Exception as e:
        print(f"DEBUG failed opening page {url}: {e}")
        return False, ""


# ==========================
# COURSE LIST RETRIEVAL
# ==========================

def _extract_course_records_recursive(obj: Any, out: list[tuple[str, str]], seen: set[str]) -> None:
    if isinstance(obj, dict):
        course_id = obj.get("id")
        fullname = obj.get("fullname") or obj.get("displayname") or obj.get("shortname")
        maybe_url = obj.get("viewurl") or obj.get("url")

        if course_id is not None and (fullname or maybe_url):
            url = str(maybe_url) if maybe_url else f"{MOODLE_ROOT_URL}course/view.php?id={course_id}"
            url = _normalize_url(url)
            name = str(fullname) if fullname else url
            if "/course/view.php?id=" in url and url not in seen:
                out.append((name, url))
                seen.add(url)

        for value in obj.values():
            _extract_course_records_recursive(value, out, seen)

    elif isinstance(obj, list):
        for item in obj:
            _extract_course_records_recursive(item, out, seen)


def _get_courses_via_ajax(session: requests.Session, sesskey: str, referer: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    attempts: list[tuple[str, dict[str, Any]]] = [
        (
            "block_mycourses_get_enrolled_courses_by_timeline_classification",
            {
                "offset": 0,
                "limit": 0,
                "classification": "firstsemester",
                "sort": "ul.timeaccess desc",
                "customfieldname": "",
                "customfieldvalue": "",
                "groupmetacourses": 0,
            },
        ),
        (
            "block_mycourses_get_enrolled_courses_by_timeline_classification",
            {
                "offset": 0,
                "limit": 0,
                "classification": "all",
                "sort": "ul.timeaccess desc",
                "customfieldname": "",
                "customfieldvalue": "",
                "groupmetacourses": 0,
            },
        ),
        (
            "core_course_get_enrolled_courses_by_timeline_classification",
            {"classification": "inprogress", "limit": 0, "offset": 0, "sort": "ul.timeaccess desc"},
        ),
        (
            "core_course_get_enrolled_courses_by_timeline_classification",
            {"classification": "future", "limit": 0, "offset": 0, "sort": "ul.timeaccess desc"},
        ),
        (
            "core_course_get_enrolled_courses_by_timeline_classification",
            {"classification": "past", "limit": 0, "offset": 0, "sort": "ul.timeaccess desc"},
        ),
    ]

    for methodname, args in attempts:
        try:
            data = _ajax_call(session, sesskey, methodname, args, referer)
            _extract_course_records_recursive(data, found, seen)
            print(f"DEBUG AJAX {methodname} returned cumulative {len(found)} courses")
            if found:
                continue
        except Exception as e:
            print(f"DEBUG AJAX {methodname} failed: {e}")

    return found


def _get_courses_from_calendar_select(driver: webdriver.Chrome) -> list[tuple[str, str]]:
    courses: list[tuple[str, str]] = []
    try:
        WebDriverWait(driver, WAIT_SEC).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "select.cal_courses_flt"))
        )
        time.sleep(2)
        select_el = driver.find_element(By.CSS_SELECTOR, "select.cal_courses_flt")
        options = select_el.find_elements(By.TAG_NAME, "option")
        for opt in options:
            try:
                val = opt.get_attribute("value")
                if not val or val == "1":
                    continue
                name = (opt.text or "").strip()
                url = f"{MOODLE_ROOT_URL}course/view.php?id={val}"
                if name:
                    courses.append((name, url))
            except Exception as opt_e:
                print(f"Warning: skipped calendar select option: {opt_e}")
                continue
    except Exception as e:
        print(f"Warning: could not read calendar select: {e}")
    return courses


def _get_courses_from_my_courses_page(session: requests.Session) -> list[tuple[str, str]]:
    html = _http_get_html(session, MY_COURSES_CLASSIC_URL)
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    courses: list[tuple[str, str]] = []
    seen: set[str] = set()
    for a in soup.select("a[href*='course/view.php?id=']"):
        href = a.get("href", "")
        if not href:
            continue
        href = _normalize_url(href)
        if href in seen:
            continue
        name = (a.get_text(" ", strip=True) or "").strip()
        if not name or len(name) < 3:
            continue
        seen.add(href)
        courses.append((name, href))
    return courses


def _get_courses_from_rendered_driver_page(driver: webdriver.Chrome) -> list[tuple[str, str]]:
    try:
        html = driver.page_source
    except Exception:
        return []

    return _extract_course_links_from_html(html)


def _get_first_accessible_moodle_html(session: requests.Session) -> tuple[str | None, str | None]:
    for url in MOODLE_PAGE_CANDIDATES:
        html = _http_get_html(session, url, referer=LOGIN_URL)
        if not html:
            continue
        if _looks_like_tau_block_page(html, ""):
            print(f"DEBUG requests page blocked: {url}")
            continue
        print(f"DEBUG requests page usable: {url}")
        return url, html
    return None, None


def get_courses_after_login(driver: webdriver.Chrome) -> list[tuple[str, str]]:
    # Strategy 0: Navigate to main dashboard — this is where cal_courses_flt lives
    print(f"Navigating to dashboard: {DASHBOARD_URL}")
    try:
        driver.get(DASHBOARD_URL)
        WebDriverWait(driver, WAIT_SEC).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        time.sleep(1.2)
    except Exception as e:
        print(f"DEBUG failed navigating to dashboard: {e}")

    # Strategy 1: Read calendar <select class="cal_courses_flt"> via Selenium (with proper wait)
    courses = _get_courses_from_calendar_select(driver)
    if courses:
        print(f"DEBUG got {len(courses)} courses from calendar select (Selenium)")
        save_course_cache(courses)
        return courses

    # Strategy 2: Read calendar <select> via BS4 on page_source
    print("Calendar select via Selenium empty — trying BS4 on page source...")
    try:
        page_source = driver.page_source
        soup = BeautifulSoup(page_source, "html.parser")
        select_el = soup.select_one("select.cal_courses_flt")
        if select_el:
            bs4_courses: list[tuple[str, str]] = []
            for opt in select_el.find_all("option"):
                val = opt.get("value", "")
                if not val or val == "1":
                    continue
                name = (opt.get_text(" ", strip=True) or "").strip()
                url = f"{MOODLE_ROOT_URL}course/view.php?id={val}"
                if name:
                    bs4_courses.append((name, url))
            if bs4_courses:
                print(f"DEBUG got {len(bs4_courses)} courses from calendar select (BS4)")
                save_course_cache(bs4_courses)
                return bs4_courses
            print("Calendar select via BS4: found 0 options")
        else:
            print("Fallback BS4: <select class='cal_courses_flt'> NOT found in page source.")
    except Exception as e:
        print(f"Warning: BS4 calendar select fallback failed: {e}")

    # Strategy 3: Try _get_courses_from_my_courses_page via requests session
    session = _session_from_selenium_cookies(driver)
    courses = _get_courses_from_my_courses_page(session)
    if courses:
        print(f"DEBUG got {len(courses)} courses from my/courses.php (requests)")
        save_course_cache(courses)
        return courses

    # Strategy 4: Parse dashboard page_source for a[href*="course/view.php?id="] links
    print("BS4 also empty — waiting for dynamic JS course links...")
    try:
        page_source = driver.page_source
        link_courses = _extract_course_links_from_html(page_source)
        if link_courses:
            print(f"DEBUG got {len(link_courses)} courses from dashboard page_source links")
            save_course_cache(link_courses)
            return link_courses
    except Exception as e:
        print(f"DEBUG failed parsing page_source links: {e}")

    # Strategy 5: Try other Moodle page candidates
    for url in MOODLE_PAGE_CANDIDATES:
        if url == DASHBOARD_URL:
            continue
        ok, html = _try_open_moodle_page_in_driver(driver, url)
        if ok:
            page_courses = _extract_course_links_from_html(html)
            if page_courses:
                print(f"DEBUG got {len(page_courses)} courses from page {url}")
                save_course_cache(page_courses)
                return page_courses

    # Strategy 6: Moodle AJAX API via requests session
    html_url, html = _get_first_accessible_moodle_html(session)
    if html:
        sesskey = _extract_sesskey_from_html(html)
        if sesskey:
            print(f"DEBUG extracted sesskey from {html_url}")
            ajax_courses = _get_courses_via_ajax(session, sesskey, html_url)
            if ajax_courses:
                print(f"DEBUG got {len(ajax_courses)} courses from Moodle AJAX")
                save_course_cache(ajax_courses)
                return ajax_courses
        else:
            print("DEBUG could not extract sesskey from usable Moodle HTML")

    # Strategy 7: Wait for dynamic JS links (a.mycourses_coursename) as last resort
    try:
        WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "a.mycourses_coursename"))
        )
        elements = driver.find_elements(By.CSS_SELECTOR, "a.mycourses_coursename")
        dyn_courses: list[tuple[str, str]] = []
        for el in elements:
            href = el.get_attribute("href") or ""
            name = (el.text or "").strip()
            if href and name and "course/view.php?id=" in href:
                dyn_courses.append((name, href))
        if dyn_courses:
            print(f"DEBUG got {len(dyn_courses)} courses from dynamic JS links")
            save_course_cache(dyn_courses)
            return dyn_courses
    except Exception as e:
        print(f"DEBUG strategy 7 (dynamic JS links) failed: {e}")

    # Fallback: use cached course list
    cached = load_course_cache()
    if cached:
        print(f"DEBUG using cached course list ({len(cached)} courses)")
        return cached

    print("Total unique courses: 0")

    # All strategies exhausted — save diagnostic info and raise
    try:
        driver.save_screenshot("debug_screenshot.png")
        print("  Saved debug_screenshot.png")
    except Exception:
        pass
    try:
        print(f"  current_url: {driver.current_url}")
        print(f"  page_source snippet:\n{driver.page_source[:3000]}")
    except Exception:
        pass
    _debug_dump_page(driver, "debug_no_courses")
    raise RuntimeError(
        "No courses found after login. "
        "All strategies for course retrieval failed."
    )


# ==========================
# SCAN HELPERS
# ==========================

def _extract_pluginfile_links_from_html(html: str) -> list[tuple[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    out: list[tuple[str, str]] = []
    for a in soup.select("a[href*='pluginfile.php']"):
        href = a.get("href")
        if not href:
            continue
        href = _normalize_url(href)
        text = _clean_html_text(a.get_text(" ", strip=True))
        out.append((href, text))
    return out


def _extract_activity_links_from_course_html(html: str) -> tuple[set[str], set[str]]:
    soup = BeautifulSoup(html, "html.parser")
    pluginfiles: set[str] = set()
    activity_pages: set[str] = set()

    for a in soup.select("a[href]"):
        href = a.get("href")
        if not href:
            continue
        href = _normalize_url(href)

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

    r = _http_head_follow(session, test_url, referer=view_url)
    if r is not None and r.url and "pluginfile.php" in r.url:
        urls.append(_normalize_url(r.url))
        return urls

    html = _http_get_html(session, view_url, referer=view_url)
    if not html:
        return urls

    for href, _txt in _extract_pluginfile_links_from_html(html):
        urls.append(href)

    return list(dict.fromkeys(urls))


def _get_last_modified_for_file(session: requests.Session, file_url: str, referer: str | None = None) -> datetime | None:
    r = _http_head_follow(session, file_url, referer=referer)
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


# ==========================
# MAIN SCAN LOGIC
# ==========================

def scan_all(session: requests.Session, courses: list[tuple[str, str]], reference_dt: datetime) -> list[FoundFile]:
    found: list[FoundFile] = []
    seen_files: set[tuple[str, str]] = set()

    for course_name_raw, course_url in courses:
        course_name_display = _course_display_name(course_name_raw)
        print(f"DEBUG scanning course: {course_name_display} | {course_url}")

        html = _http_get_html(session, course_url, referer=MOODLE_ROOT_URL)
        if not html:
            print(f"DEBUG could not fetch course page: {course_url}")
            continue

        if _looks_like_tau_block_page(html, ""):
            print(f"DEBUG course page blocked: {course_url}")
            continue

        pluginfiles, activity_pages = _extract_activity_links_from_course_html(html)

        for pf in sorted(pluginfiles):
            key = (course_url, pf)
            if key in seen_files:
                continue
            seen_files.add(key)

            lm = _get_last_modified_for_file(session, pf, referer=course_url)
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

                    lm = _get_last_modified_for_file(session, pf, referer=act)
                    if not lm:
                        continue

                    if lm > reference_dt:
                        fname = _safe_filename_from_url(pf)
                        link_for_print = _normalize_link_for_print(act, pf)
                        found.append(FoundFile(course_name_raw, course_name_display, fname, lm, link_for_print))
            else:
                act_html = _http_get_html(session, act, referer=course_url)
                if not act_html or _looks_like_tau_block_page(act_html, ""):
                    continue

                for pf, txt in _extract_pluginfile_links_from_html(act_html):
                    key = (course_url, pf)
                    if key in seen_files:
                        continue
                    seen_files.add(key)

                    lm = _get_last_modified_for_file(session, pf, referer=act)
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

def main() -> None:
    if not USERNAME or not USER_ID or not PASSWORD:
        raise SystemExit("Missing Moodle secrets: MOODLE_USERNAME / MOODLE_USER_ID / MOODLE_PASSWORD")

    run_start = datetime.now(TZ_IL)
    last_run = load_last_run()

    driver = build_driver()
    try:
        ensure_logged_in_to_sso(driver)

        courses = get_courses_after_login(driver)
        print(f"\nFound {len(courses)} courses.\n")
        for i, (name, url) in enumerate(courses[:15], start=1):
            print(f"DEBUG course {i}: {name} -> {url}")

        session = _session_from_selenium_cookies(driver)

        # HTTP fallback if Selenium gave 0 courses
        if not courses:
            courses = _get_courses_from_my_courses_page(session)
            if courses:
                print(f"DEBUG HTTP fallback got {len(courses)} courses from my/courses.php")

        results = scan_all(session, courses, last_run)

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
    try:
        main()
    except Exception:
        run_link = github_run_url()
        tb = traceback.format_exc()

        msg = "❌ Moodle scan failed (Exception)\n"
        if run_link:
            msg += f"🔗 Logs: {run_link}\n\n"
        msg += tb

        if len(msg) > 3800:
            msg = msg[:3800] + "\n...\n(Traceback clipped)"

        telegram_send(msg)
        raise
