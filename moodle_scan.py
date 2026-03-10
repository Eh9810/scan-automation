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

NEW:
- Preflight HTTP checks before Selenium:
  * https://moodle.tau.ac.il/
  * https://moodle.tau.ac.il/local/mycourses/
  * LOGIN_URL
- Detects TAU WAF / maintenance / access denied page early.
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

LOGIN_URL = "https://nidp.tau.ac.il/nidp/saml2/sso?id=10&sid=0&option=credential&sid=0"
MY_COURSES_URL = "https://moodle.tau.ac.il/local/mycourses/"
MOODLE_ROOT_URL = "https://moodle.tau.ac.il/"

TZ_IL = ZoneInfo("Asia/Jerusalem")
WAIT_SEC = 30
HEADLESS = True

STATE_FILE = "last_run.json"  # will be created/updated in repo


# ==========================
# SECRETS (from GitHub Actions)
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
# HELPERS
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


def _debug_dump_page(driver: webdriver.Chrome, prefix: str = "debug") -> None:
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


def _http_probe(url: str) -> tuple[int | None, str, str]:
    """
    Returns: (status_code_or_none, final_url, first_2000_chars)
    """
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
        }
        r = requests.get(url, headers=headers, allow_redirects=True, timeout=40)
        text = r.text if isinstance(r.text, str) else ""
        return r.status_code, r.url, text[:2000]
    except Exception as e:
        return None, url, f"EXCEPTION: {e}"


def _looks_like_tau_block_page(text: str) -> bool:
    t = text or ""
    markers = [
        "TAU Under Maintenence",
        "Under Maintenence",
        "Access denied",
        "בקשה נדחתה",
        "Please try again, or contact us for support",
        "אנא נסו שוב, או צרו קשר עם מרכז התמיכה",
        "Your support ID is:",
    ]
    return any(m in t for m in markers)


def preflight_network_access_check() -> None:
    """
    Early check: can this GitHub runner reach TAU endpoints at all?
    If blocked by TAU/WAF/maintenance page, fail immediately with a clear message.
    """
    targets = [
        ("moodle_root", MOODLE_ROOT_URL),
        ("my_courses", MY_COURSES_URL),
        ("nidp_login", LOGIN_URL),
    ]

    lines = ["=== PREFLIGHT CHECK ==="]
    blocked = False

    for name, url in targets:
        status, final_url, snippet = _http_probe(url)
        lines.append(f"[{name}] url={url}")
        lines.append(f"[{name}] status={status}")
        lines.append(f"[{name}] final_url={final_url}")
        lines.append(f"[{name}] snippet={snippet[:500]}")
        lines.append("-" * 60)

        if _looks_like_tau_block_page(snippet):
            blocked = True

    print("\n".join(lines))

    if blocked:
        raise RuntimeError(
            "Preflight failed: TAU returned an Access denied / maintenance-style page to this runner. "
            "The issue is network/server-side access from GitHub Actions, before Selenium login begins."
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
# SELENIUM: DRIVER + LOGIN
# ==========================

def build_driver() -> webdriver.Chrome:
    options = Options()
    options.add_argument("--disable-notifications")
    options.add_argument("--disable-popup-blocking")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1600,2200")
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
        "a[href*='/auth/saml2/login.php']",
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
        texts = ["התחבר", "כניסה", "Login", "Sign in"]
        for txt in texts:
            els = driver.find_elements(By.XPATH, f"//a[contains(normalize-space(.), '{txt}')]")
            for el in els:
                if el.is_displayed():
                    driver.execute_script("arguments[0].click();", el)
                    return True
    except Exception:
        pass

    return False


def ensure_logged_in_moodle(driver: webdriver.Chrome) -> None:
    wait = WebDriverWait(driver, WAIT_SEC)
    driver.get(MY_COURSES_URL)
    wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
    time.sleep(1.0)

    if click_login_if_guest(driver):
        time.sleep(1.5)

        if "nidp.tau.ac.il" in driver.current_url.lower():
            maybe_login_nidp(driver)
            ensure_on_moodle(driver)

        driver.get(MY_COURSES_URL)
        wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        time.sleep(1.0)

    def courses_or_guest(d):
        cur_url = d.current_url.lower()
        page_html = d.page_source

        if d.find_elements(By.CSS_SELECTOR, "a.mycourses_coursename"):
            return True

        if "local/mycourses" in cur_url:
            links = d.find_elements(By.CSS_SELECTOR, "a[href*='/course/view.php?id=']")
            if links:
                return True

        if "local/mycourses" in cur_url and "course/view.php?id=" in page_html:
            return True

        guest_markers = [
            "גישת אורחים",
            "Guest access",
            "אורח במערכת",
            "You are logged in as a guest",
        ]
        if any(g in page_html for g in guest_markers):
            return True

        login_markers = [
            "Ecom_User_ID",
            "Ecom_Password",
            "הזדהות אוניברסיטאית",
            "שם משתמש/ת",
            "מספר זהות",
        ]
        if any(g in page_html for g in login_markers):
            return True

        return False

    try:
        wait.until(courses_or_guest)
    except Exception:
        _debug_dump_page(driver, "debug_before_wait")
        raise

    page_html = driver.page_source
    login_markers = [
        "Ecom_User_ID",
        "Ecom_Password",
        "הזדהות אוניברסיטאית",
        "שם משתמש/ת",
        "מספר זהות",
    ]
    if any(m in page_html for m in login_markers):
        _debug_dump_page(driver, "debug_login_detected")
        raise RuntimeError("Reached Moodle flow but ended up back on TAU login page instead of MyCourses.")

    guest_markers = [
        "גישת אורחים",
        "Guest access",
        "אורח במערכת",
        "You are logged in as a guest",
    ]
    if any(g in page_html for g in guest_markers):
        _debug_dump_page(driver, "debug_guest_detected")
        raise RuntimeError("Still guest access on MyCourses; SSO did not complete automatically.")


def get_courses(driver: webdriver.Chrome) -> list[tuple[str, str]]:
    ensure_logged_in_moodle(driver)

    wait = WebDriverWait(driver, WAIT_SEC)

    def course_links_present(d):
        if d.find_elements(By.CSS_SELECTOR, "a.mycourses_coursename"):
            return True
        if "local/mycourses" in d.current_url.lower():
            if d.find_elements(By.CSS_SELECTOR, "a[href*='/course/view.php?id=']"):
                return True
            if "course/view.php?id=" in d.page_source:
                return True
        return False

    try:
        wait.until(course_links_present)
    except Exception:
        _debug_dump_page(driver, "debug_get_courses_wait")
        raise

    links_elems = []
    try:
        links_elems.extend(driver.find_elements(By.CSS_SELECTOR, "a.mycourses_coursename"))
    except Exception:
        pass

    try:
        links_elems.extend(driver.find_elements(By.CSS_SELECTOR, "a[href*='/course/view.php?id=']"))
    except Exception:
        pass

    courses: list[tuple[str, str]] = []
    for a in links_elems:
        try:
            name = (a.text or "").strip()
            href = a.get_attribute("href")
            if href and "course/view.php?id=" in href:
                if not name:
                    name = href
                courses.append((name, href))
        except Exception:
            continue

    uniq: list[tuple[str, str]] = []
    seen = set()
    for n, u in courses:
        if u not in seen:
            uniq.append((n, u))
            seen.add(u)

    print(f"DEBUG collected {len(uniq)} course links")
    for idx, (n, u) in enumerate(uniq[:20], start=1):
        print(f"DEBUG course {idx}: {n} -> {u}")

    if not uniq:
        _debug_dump_page(driver, "debug_no_courses_found")
        raise RuntimeError("No course links were found on MyCourses page.")

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
    if not USERNAME or not USER_ID or not PASSWORD:
        raise SystemExit("Missing Moodle secrets: MOODLE_USERNAME / MOODLE_USER_ID / MOODLE_PASSWORD")

    run_start = datetime.now(TZ_IL)
    last_run = load_last_run()

    # NEW: before Selenium, verify this runner can even reach TAU endpoints
    preflight_network_access_check()

    driver = build_driver()
    try:
        driver.get(LOGIN_URL)

        maybe_login_nidp(driver)
        ensure_on_moodle(driver)

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
