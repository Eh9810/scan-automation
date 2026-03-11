from __future__ import annotations

# -*- coding: utf-8 -*-
"""
TAU Moodle scanner (GitHub Actions-ready)

Flow:
1) Log in to TAU NIDP with Selenium
2) Establish a Moodle session
3) Collect enrolled course links
4) Scan each course for files changed since the last run
5) Send Telegram only when there are updates
"""

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import unquote, urlparse, urljoin
import json
import os
import re
import time
import traceback

import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support.ui import WebDriverWait

try:
    from bs4 import BeautifulSoup
except ImportError:
    raise SystemExit("Missing bs4. Install: pip install beautifulsoup4")

try:
    from zoneinfo import ZoneInfo
except ImportError:
    raise SystemExit("Missing zoneinfo (Python 3.9+).")


LOGIN_URL = "https://nidp.tau.ac.il/nidp/saml2/sso?id=10&sid=0&option=credential&sid=0"
MOODLE_ROOT_URL = "https://moodle.tau.ac.il/"
MY_COURSES_URL = "https://moodle.tau.ac.il/local/mycourses/"
MY_URL = "https://moodle.tau.ac.il/my/"
MY_COURSES_PHP_URL = "https://moodle.tau.ac.il/my/courses.php"

TZ_IL = ZoneInfo("Asia/Jerusalem")
WAIT_SEC = 35
HEADLESS = True
STATE_FILE = "last_run.json"


USERNAME = os.environ.get("MOODLE_USERNAME", "")
USER_ID = os.environ.get("MOODLE_USER_ID", "")
PASSWORD = os.environ.get("MOODLE_PASSWORD", "")

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")


@dataclass(frozen=True)
class FoundFile:
    course_name_raw: str
    course_name_display: str
    file_name: str
    last_modified_il: datetime
    link: str


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


def _parse_http_last_modified(headers: requests.structures.CaseInsensitiveDict) -> datetime | None:
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


def _page_looks_blocked(page_source: str, title: str = "", current_url: str = "") -> bool:
    text = f"{title}\n{current_url}\n{page_source}".lower()
    markers = [
        "tau under maintenence",
        "tau under maintenance",
        "access denied",
        "please try again, or contact us for support",
        "your support id is:",
        "בקשה נדחתה",
        "אנא נסו שוב, או צרו קשר עם מרכז התמיכה",
    ]
    return any(m in text for m in markers)


def _extract_sesskey_from_html(html: str) -> str:
    if not html:
        return ""

    patterns = [
        r'"sesskey"\s*:\s*"([^"]+)"',
        r"'sesskey'\s*:\s*'([^']+)'",
        r'sesskey=([A-Za-z0-9]+)',
        r'name="sesskey"\s+value="([^"]+)"',
    ]
    for pattern in patterns:
        m = re.search(pattern, html)
        if m:
            return m.group(1)

    return ""


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


def build_driver() -> webdriver.Chrome:
    options = Options()
    options.add_argument("--disable-notifications")
    options.add_argument("--disable-popup-blocking")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1600,2200")
    options.add_argument("--lang=he-IL")
    if HEADLESS:
        options.add_argument("--headless=new")
    return webdriver.Chrome(options=options)


def _find_any_visible(driver: webdriver.Chrome, by: str, values: list[str]) -> WebElement | None:
    for value in values:
        try:
            el = driver.find_element(by, value)
            if el.is_displayed() and el.is_enabled():
                return el
        except Exception:
            continue
    return None


def _safe_fill(driver: webdriver.Chrome, el: WebElement, value: str) -> None:
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
            el, value
        )


def login_via_nidp(driver: webdriver.Chrome) -> None:
    wait = WebDriverWait(driver, WAIT_SEC)
    driver.get(LOGIN_URL)

    user_ids = ["Ecom_User_ID", "Ecom_UserID", "Ecom_Username", "username", "user"]
    pid_ids = ["Ecom_Taz", "Ecom_User_Pid", "Ecom_Pid", "pid", "tz"]
    pass_ids = ["Ecom_Password", "Ecom_Pass", "password", "pass"]

    def form_ready(d: webdriver.Chrome) -> bool:
        return (
            _find_any_visible(d, By.ID, user_ids) is not None
            and _find_any_visible(d, By.ID, pass_ids) is not None
        )

    wait.until(form_ready)

    user_field = _find_any_visible(driver, By.ID, user_ids)
    pass_field = _find_any_visible(driver, By.ID, pass_ids)
    pid_field = _find_any_visible(driver, By.ID, pid_ids)

    if not user_field or not pass_field:
        _debug_dump_page(driver, "debug_nidp_fields_missing")
        raise RuntimeError("Could not find TAU NIDP login fields.")

    _safe_fill(driver, user_field, USERNAME)
    if pid_field:
        _safe_fill(driver, pid_field, USER_ID)
    _safe_fill(driver, pass_field, PASSWORD)
    pass_field.send_keys(Keys.RETURN)


def _submit_forms_if_needed(driver: webdriver.Chrome) -> bool:
    xpaths = [
        "//button[@type='submit']",
        "//input[@type='submit']",
        "//button[contains(., 'Continue')]",
        "//button[contains(., 'המשך')]",
        "//button[contains(., 'כניסה')]",
        "//input[@value='Continue']",
    ]

    for xp in xpaths:
        try:
            els = driver.find_elements(By.XPATH, xp)
            for el in els:
                if el.is_displayed() and el.is_enabled():
                    driver.execute_script("arguments[0].click();", el)
                    time.sleep(1.2)
                    return True
        except Exception:
            pass

    try:
        forms = driver.find_elements(By.TAG_NAME, "form")
        for form in forms:
            if form.is_displayed():
                driver.execute_script("arguments[0].submit();", form)
                time.sleep(1.2)
                return True
    except Exception:
        pass

    return False


def _has_moodle_session_cookie(driver: webdriver.Chrome) -> bool:
    try:
        for c in driver.get_cookies():
            name = c.get("name", "")
            domain = c.get("domain", "")
            if "moodle" in domain and name.lower().startswith("moodlesession"):
                return True
    except Exception:
        pass
    return False


def _page_has_logged_in_moodle_signs(driver: webdriver.Chrome) -> bool:
    try:
        html = driver.page_source
    except Exception:
        return False

    if _extract_sesskey_from_html(html):
        return True

    signs = [
        "data-userid",
        "usermenu",
        "logout.php",
        "sesskey",
        "/my/",
        "/course/view.php?id=",
    ]
    text = html.lower()
    return any(s.lower() in text for s in signs)


def wait_for_moodle_session(driver: webdriver.Chrome) -> None:
    deadline = time.time() + 75

    while time.time() < deadline:
        try:
            current_url = driver.current_url
        except Exception:
            current_url = ""

        try:
            title = driver.title
        except Exception:
            title = ""

        try:
            html = driver.page_source
        except Exception:
            html = ""

        if "nidp.tau.ac.il" in current_url.lower():
            _submit_forms_if_needed(driver)
            time.sleep(1.0)
            continue

        if "moodle.tau.ac.il" in current_url.lower():
            if not _page_looks_blocked(html, title, current_url):
                if _has_moodle_session_cookie(driver) or _page_has_logged_in_moodle_signs(driver):
                    return

            _submit_forms_if_needed(driver)
            time.sleep(1.0)
            continue

        time.sleep(1.0)

    _debug_dump_page(driver, "debug_no_session_after_nidp")
    raise RuntimeError("NIDP login finished, but Moodle session was not established afterwards.")


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


def _extract_course_links_from_html(html: str, base_url: str) -> list[tuple[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    out: list[tuple[str, str]] = []
    seen = set()

    for a in soup.select("a[href]"):
        href = (a.get("href") or "").strip()
        if not href:
            continue

        abs_href = urljoin(base_url, href)
        if "course/view.php?id=" not in abs_href:
            continue

        name = (a.get_text(" ", strip=True) or "").strip()
        if abs_href not in seen:
            out.append((name or abs_href, abs_href))
            seen.add(abs_href)

    return out


def _collect_courses_via_ajax(session: requests.Session, sesskey: str) -> list[tuple[str, str]]:
    if not sesskey:
        return []

    url = (
        f"{MOODLE_ROOT_URL}lib/ajax/service.php"
        f"?sesskey={sesskey}"
        f"&info=block_mycourses_get_enrolled_courses_by_timeline_classification"
    )

    classifications = [
        "inprogress",
        "future",
        "all",
        "past",
    ]

    out: list[tuple[str, str]] = []
    seen = set()

    for classification in classifications:
        payload = [
            {
                "index": 0,
                "methodname": "block_mycourses_get_enrolled_courses_by_timeline_classification",
                "args": {
                    "offset": 0,
                    "limit": 0,
                    "classification": classification,
                    "sort": "ul.timeaccess desc",
                    "customfieldname": "",
                    "customfieldvalue": "",
                    "groupmetacourses": 0,
                },
            }
        ]

        try:
            r = session.post(
                url,
                json=payload,
                timeout=40,
                headers={
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                },
            )
            if r.status_code >= 400:
                continue
            data = r.json()
        except Exception:
            continue

        def walk(obj: object) -> None:
            if isinstance(obj, dict):
                href = ""
                name = ""

                for key in ("viewurl", "courseurl", "url", "link"):
                    value = obj.get(key)
                    if isinstance(value, str) and "course/view.php?id=" in value:
                        href = value
                        break

                for key in ("displayname", "fullname", "shortname", "name"):
                    value = obj.get(key)
                    if isinstance(value, str) and value.strip():
                        name = value.strip()
                        break

                if href and href not in seen:
                    out.append((name or href, href))
                    seen.add(href)

                for value in obj.values():
                    walk(value)

            elif isinstance(obj, list):
                for item in obj:
                    walk(item)

        walk(data)

    return out


def ensure_logged_in_moodle(driver: webdriver.Chrome) -> None:
    login_via_nidp(driver)
    wait_for_moodle_session(driver)


def get_courses(driver: webdriver.Chrome) -> list[tuple[str, str]]:
    ensure_logged_in_moodle(driver)

    session = _session_from_selenium_cookies(driver)
    html_sources: list[tuple[str, str]] = []

    try:
        current_html = driver.page_source
        current_url = driver.current_url
        if current_html:
            html_sources.append((current_url, current_html))
    except Exception:
        pass

    candidate_pages = [
        MY_COURSES_URL,
        MY_COURSES_PHP_URL,
        MY_URL,
    ]

    for url in candidate_pages:
        try:
            driver.get(url)
            time.sleep(2.0)
            html = driver.page_source
            title = driver.title
            print(f"DEBUG tried page {url} | title={title!r} | blocked={_page_looks_blocked(html, title, url)}")
            if html and not _page_looks_blocked(html, title, url):
                html_sources.append((url, html))
        except Exception:
            continue

    sesskey = ""
    for _url, html in html_sources:
        sesskey = _extract_sesskey_from_html(html)
        if sesskey:
            break

    courses: list[tuple[str, str]] = []
    seen = set()

    if sesskey:
        for name, href in _collect_courses_via_ajax(session, sesskey):
            if href not in seen:
                courses.append((name, href))
                seen.add(href)

    for base_url, html in html_sources:
        for name, href in _extract_course_links_from_html(html, base_url):
            if href not in seen:
                courses.append((name, href))
                seen.add(href)

    if not courses:
        _debug_dump_page(driver, "debug_no_courses")
        raise RuntimeError("Could not retrieve course list after SSO.")

    print(f"DEBUG collected {len(courses)} course links")
    for idx, (name, href) in enumerate(courses[:20], start=1):
        print(f"DEBUG course {idx}: {name} -> {href}")

    return courses


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
        href = (a.get("href") or "").strip()
        if not href:
            continue

        if "pluginfile.php/" in href:
            pluginfiles.add(href)
            continue

        if "mod/resource/view.php" in href:
            activity_pages.add(href)
        elif "mod/folder/view.php" in href:
            activity_pages.add(href)
        elif "mod/assign/view.php" in href:
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


def main() -> None:
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
