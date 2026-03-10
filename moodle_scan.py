# -*- coding: utf-8 -*-
"""
TAU Moodle scanner (GitHub Actions-ready)

Strategy:
1) Start from Moodle side (not generic NIDP URL):
   - try /local/mycourses/
   - or /login/index.php
   - click "התחבר/י" / SAML login if needed
2) Reach NIDP login form
3) Submit credentials
4) Wait for the real SAML handoff page and submit hidden SAMLResponse form if present
5) Wait until Moodle shows actual logged-in markers
6) Open a usable courses page and collect courses
7) Scan updated files and send Telegram only on updates/errors
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
from selenium.common.exceptions import TimeoutException, NoSuchElementException
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

MY_COURSES_URL = "https://moodle.tau.ac.il/local/mycourses/"
MY_COURSES_PHP_URL = "https://moodle.tau.ac.il/my/courses.php"
MY_URL = "https://moodle.tau.ac.il/my/"
MOODLE_LOGIN_URL = "https://moodle.tau.ac.il/login/index.php"
MOODLE_SAML_URL = "https://moodle.tau.ac.il/auth/saml2/login.php"

MOODLE_ENTRY_URLS = [
    MY_COURSES_URL,
    MOODLE_LOGIN_URL,
    MY_COURSES_PHP_URL,
    MY_URL,
]

TZ_IL = ZoneInfo("Asia/Jerusalem")
WAIT_SEC = 40
SHORT_WAIT = 8
HEADLESS = True
STATE_FILE = "last_run.json"


# ==========================
# SECRETS
# ==========================

USERNAME = os.environ.get("MOODLE_USERNAME", "").strip()
USER_ID = os.environ.get("MOODLE_USER_ID", "").strip()
PASSWORD = os.environ.get("MOODLE_PASSWORD", "").strip()

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()


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
# GENERIC HELPERS
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
        if ua:
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
    print(f"DEBUG {prefix} page source snippet:\n{page_source[:6000]}")

    try:
        with open(f"{prefix}.html", "w", encoding="utf-8") as f:
            f.write(page_source)
        print(f"DEBUG saved HTML to {prefix}.html")
    except Exception as e:
        print(f"DEBUG failed saving HTML: {e}")

    try:
        driver.save_screenshot(f"{prefix}.png")
        print(f"DEBUG saved screenshot to {prefix}.png")
    except Exception as e:
        print(f"DEBUG failed saving screenshot: {e}")


# ==========================
# STATE
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
# PAGE DETECTION
# ==========================

def _page_source(driver: webdriver.Chrome) -> str:
    try:
        return driver.page_source or ""
    except Exception:
        return ""


def _page_title(driver: webdriver.Chrome) -> str:
    try:
        return driver.title or ""
    except Exception:
        return ""


def is_tau_block_page(driver: webdriver.Chrome) -> bool:
    title = _page_title(driver).lower()
    html = _page_source(driver).lower()

    markers = [
        "tau under maintenence",
        "tau under maintenance",
        "access denied",
        "בקשה נדחתה",
        "אנא נסו שוב",
        "please try again, or contact us for support",
    ]
    return any(m in title or m in html for m in markers)


def is_nidp_login_page(driver: webdriver.Chrome) -> bool:
    url = (driver.current_url or "").lower()
    html = _page_source(driver)

    if "nidp.tau.ac.il" not in url:
        return False

    id_markers = [
        "Ecom_User_ID",
        "Ecom_UserID",
        "Ecom_Taz",
        "Ecom_Password",
    ]
    return any(marker in html for marker in id_markers)


def has_saml_response_form(driver: webdriver.Chrome) -> bool:
    html = _page_source(driver)
    if "SAMLResponse" in html:
        return True
    try:
        driver.find_element(By.CSS_SELECTOR, "input[name='SAMLResponse']")
        return True
    except Exception:
        return False


def is_logged_in_moodle_page(driver: webdriver.Chrome) -> bool:
    url = (driver.current_url or "").lower()
    html = _page_source(driver)

    if "moodle.tau.ac.il" not in url:
        return False

    markers = [
        "את/ה מחובר/ת כ:",
        "logout.php?sesskey=",
        '"sesskey":"',
        '"userid":',
        '"userId":',
        "M.cfg =",
        "M.cfg = {",
        "data-region=\"mycourses\"",
    ]
    return any(m in html for m in markers)


def has_course_links(driver: webdriver.Chrome) -> bool:
    selectors = [
        "a.mycourses_coursename",
        "a[href*='/course/view.php?id=']",
    ]
    for sel in selectors:
        try:
            if driver.find_elements(By.CSS_SELECTOR, sel):
                return True
        except Exception:
            pass

    html = _page_source(driver)
    return "course/view.php?id=" in html


def has_login_link_on_moodle(driver: webdriver.Chrome) -> bool:
    if "moodle.tau.ac.il" not in (driver.current_url or "").lower():
        return False

    selectors = [
        "#usernavigation a[href*='/login/index.php']",
        "a[href='https://moodle.tau.ac.il/login/index.php']",
        "a[href*='moodle.tau.ac.il/login/index.php']",
        "a[href*='/auth/saml2/login.php']",
    ]
    for sel in selectors:
        try:
            if driver.find_elements(By.CSS_SELECTOR, sel):
                return True
        except Exception:
            pass
    return False


# ==========================
# DRIVER
# ==========================

def build_driver() -> webdriver.Chrome:
    options = Options()
    options.add_argument("--disable-notifications")
    options.add_argument("--disable-popup-blocking")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1600,2400")
    if HEADLESS:
        options.add_argument("--headless=new")
    return webdriver.Chrome(options=options)


# ==========================
# UI HELPERS
# ==========================

def wait_body(driver: webdriver.Chrome, timeout: int = WAIT_SEC) -> None:
    WebDriverWait(driver, timeout).until(
        EC.presence_of_element_located((By.TAG_NAME, "body"))
    )


def click_visible(driver: webdriver.Chrome, selectors: list[str]) -> bool:
    for sel in selectors:
        try:
            els = driver.find_elements(By.CSS_SELECTOR, sel)
            for el in els:
                if el.is_displayed() and el.is_enabled():
                    driver.execute_script("arguments[0].click();", el)
                    return True
        except Exception:
            pass
    return False


def click_text_link(driver: webdriver.Chrome, texts: list[str]) -> bool:
    for txt in texts:
        try:
            els = driver.find_elements(By.XPATH, f"//a[contains(normalize-space(.), '{txt}')]")
            for el in els:
                if el.is_displayed():
                    driver.execute_script("arguments[0].click();", el)
                    return True
        except Exception:
            pass
    return False


# ==========================
# NIDP LOGIN
# ==========================

def _find_any(driver: webdriver.Chrome, by: By, values: list[str]):
    for v in values:
        try:
            el = driver.find_element(by, v)
            if el.is_displayed() and el.is_enabled():
                return el
        except Exception:
            continue
    return None


def _safe_fill(driver: webdriver.Chrome, el, value: str) -> None:
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
            el,
            value,
        )


def maybe_login_nidp(driver: webdriver.Chrome) -> None:
    wait = WebDriverWait(driver, WAIT_SEC)

    user_ids = ["Ecom_User_ID", "Ecom_UserID", "Ecom_Username", "username", "user"]
    pid_ids = ["Ecom_Taz", "Ecom_User_Pid", "Ecom_Pid", "pid", "tz"]
    pass_ids = ["Ecom_Password", "Ecom_Pass", "password", "pass"]

    wait.until(lambda d: is_nidp_login_page(d))

    user_field = _find_any(driver, By.ID, user_ids)
    pid_field = _find_any(driver, By.ID, pid_ids)
    pass_field = _find_any(driver, By.ID, pass_ids)

    if user_field:
        _safe_fill(driver, user_field, USERNAME)
    if pid_field:
        _safe_fill(driver, pid_field, USER_ID)
    if pass_field:
        _safe_fill(driver, pass_field, PASSWORD)
    else:
        raise RuntimeError("NIDP password field was not found.")

    submit_selectors = [
        "button[type='submit']",
        "input[type='submit']",
        "button.btn-primary",
        "button.login-btn",
    ]

    clicked = False
    for sel in submit_selectors:
        try:
            els = driver.find_elements(By.CSS_SELECTOR, sel)
            for el in els:
                if el.is_displayed() and el.is_enabled():
                    driver.execute_script("arguments[0].click();", el)
                    clicked = True
                    break
            if clicked:
                break
        except Exception:
            pass

    if not clicked:
        pass_field.send_keys(Keys.RETURN)

    time.sleep(2.0)


# ==========================
# MOODLE SSO FLOW
# ==========================

def start_from_moodle_side(driver: webdriver.Chrome) -> None:
    """
    Important:
    Start from Moodle, not from a generic NIDP URL.
    This ensures Moodle creates the proper SAML request/relaystate.
    """
    texts = ["התחבר/י", "התחבר", "כניסה", "Login", "Sign in"]
    selectors = [
        "#usernavigation a[href*='/login/index.php']",
        "a[href='https://moodle.tau.ac.il/login/index.php']",
        "a[href*='moodle.tau.ac.il/login/index.php']",
        "a[href*='/auth/saml2/login.php']",
    ]

    last_error = None

    for url in MOODLE_ENTRY_URLS:
        try:
            driver.get(url)
            wait_body(driver, SHORT_WAIT)
            time.sleep(1.2)

            if is_nidp_login_page(driver):
                return

            if has_login_link_on_moodle(driver):
                if click_visible(driver, selectors) or click_text_link(driver, texts):
                    time.sleep(2.0)
                    return

            # Sometimes login/index.php immediately redirects
            cur = (driver.current_url or "").lower()
            if "auth/saml2/login.php" in cur or "nidp.tau.ac.il" in cur:
                time.sleep(1.5)
                return

        except Exception as e:
            last_error = e
            continue

    # direct SAML URL as last Moodle-side fallback
    driver.get(MOODLE_SAML_URL)
    wait_body(driver, SHORT_WAIT)
    time.sleep(1.5)

    if is_nidp_login_page(driver):
        return

    if last_error:
        print(f"DEBUG start_from_moodle_side previous error: {last_error}")


def maybe_submit_saml_response_form(driver: webdriver.Chrome) -> bool:
    """
    After NIDP login there is often a hidden SAMLResponse form that auto-submits.
    In headless mode we submit it ourselves if needed.
    """
    if not has_saml_response_form(driver):
        return False

    try:
        form = driver.find_element(By.XPATH, "//form[.//input[@name='SAMLResponse']]")
    except NoSuchElementException:
        form = None

    if form is not None:
        try:
            driver.execute_script("arguments[0].submit();", form)
            time.sleep(2.5)
            return True
        except Exception:
            pass

    try:
        btn = driver.find_element(By.CSS_SELECTOR, "form input[type='submit'], form button[type='submit']")
        driver.execute_script("arguments[0].click();", btn)
        time.sleep(2.5)
        return True
    except Exception:
        pass

    return False


def wait_for_moodle_session(driver: webdriver.Chrome) -> None:
    """
    Wait for natural redirect / SAML handoff.
    Do not navigate away too early.
    """
    end_time = time.time() + 70
    saw_saml_form = False

    while time.time() < end_time:
        try:
            wait_body(driver, SHORT_WAIT)
        except Exception:
            pass

        if has_saml_response_form(driver):
            saw_saml_form = True
            maybe_submit_saml_response_form(driver)

        if is_logged_in_moodle_page(driver):
            return

        if has_course_links(driver):
            return

        # If we're still on NIDP portal/login, keep waiting a bit longer
        cur = (driver.current_url or "").lower()
        if "nidp.tau.ac.il" in cur:
            time.sleep(1.5)
            continue

        # If on Moodle but no markers yet, allow more time for JS/redirect
        if "moodle.tau.ac.il" in cur:
            time.sleep(1.5)
            continue

        time.sleep(1.2)

    if saw_saml_form:
        _debug_dump_page(driver, "debug_saml_form_seen_but_no_session")
        raise RuntimeError("SAMLResponse form was seen/submitted, but Moodle session was not established.")
    else:
        _debug_dump_page(driver, "debug_no_session_after_nidp")
        raise RuntimeError("NIDP login finished, but Moodle session was not established afterwards.")


def ensure_logged_in_moodle(driver: webdriver.Chrome) -> None:
    start_from_moodle_side(driver)

    if is_nidp_login_page(driver):
        maybe_login_nidp(driver)

    wait_for_moodle_session(driver)

    # Now that session exists, try a few course landing pages
    for target in [MY_COURSES_URL, MY_COURSES_PHP_URL, MY_URL]:
        try:
            driver.get(target)
            wait_body(driver, SHORT_WAIT)
            time.sleep(1.5)

            if is_logged_in_moodle_page(driver) and (has_course_links(driver) or "moodle.tau.ac.il" in (driver.current_url or "").lower()):
                return
        except Exception:
            continue

    _debug_dump_page(driver, "debug_logged_in_no_usable_courses_page")
    raise RuntimeError("Logged into Moodle, but could not open a usable courses page.")


# ==========================
# COURSE EXTRACTION
# ==========================

def extract_courses_from_page(driver: webdriver.Chrome) -> list[tuple[str, str]]:
    links_elems = []
    selectors = [
        "a.mycourses_coursename",
        "a[href*='/course/view.php?id=']",
    ]

    for sel in selectors:
        try:
            links_elems.extend(driver.find_elements(By.CSS_SELECTOR, sel))
        except Exception:
            pass

    courses: list[tuple[str, str]] = []
    seen = set()

    for a in links_elems:
        try:
            href = a.get_attribute("href") or ""
            name = (a.text or "").strip()
            if "course/view.php?id=" not in href:
                continue
            if not name:
                name = href
            if href not in seen:
                seen.add(href)
                courses.append((name, href))
        except Exception:
            continue

    if not courses:
        html = _page_source(driver)
        matches = re.findall(r'href="(https://moodle\.tau\.ac\.il/course/view\.php\?id=\d+)"', html)
        seen = set()
        for href in matches:
            if href not in seen:
                seen.add(href)
                courses.append((href, href))

    return courses


def get_courses(driver: webdriver.Chrome) -> list[tuple[str, str]]:
    ensure_logged_in_moodle(driver)

    for target in [MY_COURSES_URL, MY_COURSES_PHP_URL, MY_URL]:
        try:
            driver.get(target)
            wait_body(driver, SHORT_WAIT)
            time.sleep(1.5)

            if not is_logged_in_moodle_page(driver):
                continue

            courses = extract_courses_from_page(driver)
            if courses:
                print(f"DEBUG collected {len(courses)} course links from {target}")
                for idx, (n, u) in enumerate(courses[:20], start=1):
                    print(f"DEBUG course {idx}: {n} -> {u}")
                return courses
        except Exception:
            continue

    _debug_dump_page(driver, "debug_no_courses_found")
    raise RuntimeError("No course links were found on any Moodle courses page.")


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
    if not USERNAME or not USER_ID or not PASSWORD:
        raise SystemExit("Missing Moodle secrets: MOODLE_USERNAME / MOODLE_USER_ID / MOODLE_PASSWORD")

    run_start = datetime.now(TZ_IL)
    last_run = load_last_run()

    driver = build_driver()
    try:
        courses = get_courses(driver)
        print(f"\nFound {len(courses)} courses.\n")

        session = _session_from_selenium_cookies(driver)
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
