# -*- coding: utf-8 -*-
"""
TAU Moodle scanner (GitHub Actions-ready)

מה הקוד הזה עושה:
1) פותח Chrome בתוך Xvfb (כלומר דפדפן "אמיתי" לא-headless, גם על GitHub Actions)
2) נכנס קודם ל-https://moodle.tau.ac.il/local/mycourses/
3) לוחץ על "התחבר/י"
4) ממלא NIDP
5) מוודא שנוצרה session אמיתית של Moodle
6) שולף קורסים (HTML + AJAX אם יש sesskey)
7) סורק קבצים חדשים/שעודכנו ושולח לטלגרם
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
import shutil
import subprocess

import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
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

MOODLE_ROOT_URL = "https://moodle.tau.ac.il/"
MY_COURSES_URL = "https://moodle.tau.ac.il/local/mycourses/"
MOODLE_LOGIN_INDEX_URL = "https://moodle.tau.ac.il/login/index.php"
MOODLE_SAML_LOGIN_URL = "https://moodle.tau.ac.il/auth/saml2/login.php"
LOGIN_URL = "https://nidp.tau.ac.il/nidp/saml2/sso?id=10&sid=0&option=credential&sid=0"

TZ_IL = ZoneInfo("Asia/Jerusalem")
WAIT_SEC = 35
PAGE_SETTLE_SEC = 1.3
STATE_FILE = "last_run.json"

# חשוב: ב-GitHub Actions נריץ non-headless בתוך Xvfb
FORCE_HEADLESS = os.environ.get("FORCE_HEADLESS", "").strip().lower() in {"1", "true", "yes"}
USE_XVFB = os.environ.get("USE_XVFB", "1").strip().lower() not in {"0", "false", "no"}

MAX_LOGIN_ATTEMPTS = 2
MAX_SESSION_WAIT_SEC = 45

# ==========================
# SECRETS (GitHub Actions)
# ==========================

USERNAME = os.environ.get("MOODLE_USERNAME", "").strip()
USER_ID = os.environ.get("MOODLE_USER_ID", "").strip()
PASSWORD = os.environ.get("MOODLE_PASSWORD", "").strip()

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()


# ==========================
# GLOBALS
# ==========================

_XVFB_PROCESS = None


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

def _contains_any(text: str, needles: list[str]) -> bool:
    text = text or ""
    return any(n in text for n in needles)


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


def _current_url(driver: webdriver.Chrome) -> str:
    try:
        return driver.current_url or ""
    except Exception:
        return ""


def _wait_body(driver: webdriver.Chrome, timeout: int = WAIT_SEC) -> None:
    WebDriverWait(driver, timeout).until(EC.presence_of_element_located((By.TAG_NAME, "body")))


def _sleep_small(sec: float = PAGE_SETTLE_SEC) -> None:
    time.sleep(sec)


def _debug_dump_page(driver: webdriver.Chrome, prefix: str = "debug") -> None:
    current_url = _current_url(driver)
    title = _page_title(driver)
    page_source = _page_source(driver)

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


# ==========================
# BLOCK / STATE DETECTION
# ==========================

def _is_tau_block_page(driver: webdriver.Chrome) -> bool:
    html = _page_source(driver)
    title = _page_title(driver)
    url = _current_url(driver)

    markers = [
        "TAU Under Maintenence",
        "Access denied.",
        "Please try again, or contact us for support.",
        "בקשה נדחתה",
        "אנא נסו שוב, או צרו קשר עם מרכז התמיכה.",
        "Your support ID is:",
    ]

    if _contains_any(title, markers):
        return True
    if _contains_any(html, markers):
        return True

    # לפעמים הכותרת ריקה אבל הדף חסימה
    if "moodle.tau.ac.il" in url and "header-inner" in html and "Your support ID is:" in html:
        return True

    return False


def _is_nidp_login_page(driver: webdriver.Chrome) -> bool:
    url = _current_url(driver).lower()
    html = _page_source(driver)

    if "nidp.tau.ac.il" in url:
        return True

    markers = [
        'id="Ecom_User_ID"',
        'id="Ecom_Password"',
        'translation_key="PAGE_TITLE"',
        "TAU Login Page",
        "Ecom_User_ID",
        "Ecom_Password",
        "הזדהות אוניברסיטאית",
    ]
    return _contains_any(html, markers)


def _is_moodle_logged_in_page(driver: webdriver.Chrome) -> bool:
    url = _current_url(driver).lower()
    html = _page_source(driver)

    if "moodle.tau.ac.il" not in url:
        return False

    if _is_tau_block_page(driver):
        return False

    logged_in_markers = [
        "/login/logout.php?sesskey=",
        "logout.php?sesskey=",
        '"sesskey":"',
        '"userid":',
        '"userId":',
        "את/ה מחובר/ת כ:",
        'data-user-id="',
        "usermenu",
    ]

    if _contains_any(html, logged_in_markers):
        return True

    # אם עדיין מופיע login link מפורש, כנראה לא מחובר
    if '/login/index.php">התחבר/י<' in html or "href=\"https://moodle.tau.ac.il/login/index.php\"" in html:
        return False

    return False


def _extract_sesskey_from_html(html: str) -> str:
    html = html or ""

    patterns = [
        r'"sesskey"\s*:\s*"([^"]+)"',
        r"sesskey=([A-Za-z0-9]+)",
        r"'sesskey'\s*:\s*'([^']+)'",
        r'"logoutUrl":"[^"]*sesskey=([^"&]+)',
    ]
    for pat in patterns:
        m = re.search(pat, html)
        if m:
            return m.group(1)
    return ""


def _find_visible(driver: webdriver.Chrome, by: By, values: list[str]):
    for v in values:
        try:
            el = driver.find_element(by, v)
            if el.is_displayed() and el.is_enabled():
                return el
        except Exception:
            continue
    return None


def _click_first_css(driver: webdriver.Chrome, selectors: list[str]) -> bool:
    for sel in selectors:
        try:
            els = driver.find_elements(By.CSS_SELECTOR, sel)
            for el in els:
                if el.is_displayed() and el.is_enabled():
                    driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
                    _sleep_small(0.3)
                    try:
                        el.click()
                    except Exception:
                        driver.execute_script("arguments[0].click();", el)
                    return True
        except Exception:
            continue
    return False


def _click_first_xpath(driver: webdriver.Chrome, xpaths: list[str]) -> bool:
    for xp in xpaths:
        try:
            els = driver.find_elements(By.XPATH, xp)
            for el in els:
                if el.is_displayed() and el.is_enabled():
                    driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
                    _sleep_small(0.3)
                    try:
                        el.click()
                    except Exception:
                        driver.execute_script("arguments[0].click();", el)
                    return True
        except Exception:
            continue
    return False


# ==========================
# XVFB + DRIVER
# ==========================

def _start_xvfb_if_needed() -> None:
    global _XVFB_PROCESS

    if FORCE_HEADLESS:
        return

    if os.environ.get("DISPLAY"):
        return

    if not USE_XVFB:
        return

    xvfb_path = shutil.which("Xvfb")
    if not xvfb_path:
        print("DEBUG Xvfb not found; continuing without Xvfb.")
        return

    display = ":99"
    os.environ["DISPLAY"] = display

    try:
        _XVFB_PROCESS = subprocess.Popen(
            [xvfb_path, display, "-screen", "0", "1920x1080x24", "-ac", "+extension", "RANDR"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1.5)
        print(f"DEBUG Xvfb started on {display}")
    except Exception as e:
        _XVFB_PROCESS = None
        print(f"DEBUG failed starting Xvfb: {e}")


def _stop_xvfb() -> None:
    global _XVFB_PROCESS
    try:
        if _XVFB_PROCESS is not None:
            _XVFB_PROCESS.terminate()
            _XVFB_PROCESS.wait(timeout=3)
    except Exception:
        pass
    _XVFB_PROCESS = None


def build_driver() -> webdriver.Chrome:
    _start_xvfb_if_needed()

    options = Options()
    options.add_argument("--disable-notifications")
    options.add_argument("--disable-popup-blocking")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--window-size=1600,2200")
    options.add_argument("--lang=he-IL")
    options.add_argument("--start-maximized")
    options.add_argument("--force-device-scale-factor=1")
    options.add_argument(
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
    )

    if FORCE_HEADLESS:
        options.add_argument("--headless=new")

    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)

    service = Service()
    driver = webdriver.Chrome(service=service, options=options)
    driver.set_page_load_timeout(90)

    try:
        driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {
                "source": """
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    Object.defineProperty(navigator, 'languages', {get: () => ['he-IL', 'he', 'en-US', 'en']});
                    Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
                    window.chrome = { runtime: {} };
                """
            },
        )
    except Exception:
        pass

    return driver


# ==========================
# HTTP SESSION HELPERS
# ==========================

def _session_from_selenium_cookies(driver: webdriver.Chrome) -> requests.Session:
    s = requests.Session()
    try:
        ua = driver.execute_script("return navigator.userAgent;")
        if ua:
            s.headers.update({"User-Agent": ua})
    except Exception:
        pass

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


# ==========================
# HTML / COURSE PARSING
# ==========================

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
# LOGIN FLOW
# ==========================

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
        return
    except Exception:
        driver.execute_script(
            "arguments[0].value = arguments[1];"
            "arguments[0].dispatchEvent(new Event('input', {bubbles:true}));"
            "arguments[0].dispatchEvent(new Event('change', {bubbles:true}));",
            el, value
        )


def handle_saml_post_form_if_present(driver: webdriver.Chrome) -> bool:
    html = _page_source(driver)
    if "SAMLResponse" not in html:
        return False

    try:
        forms = driver.find_elements(By.TAG_NAME, "form")
        for form in forms:
            action = (form.get_attribute("action") or "").lower()
            if "moodle.tau.ac.il" in action or "auth/saml2/login.php" in action:
                print(f"DEBUG submitting SAML form manually -> {action}")
                driver.execute_script("arguments[0].submit();", form)
                return True
    except Exception:
        pass

    return False


def maybe_login_nidp(driver: webdriver.Chrome) -> None:
    wait = WebDriverWait(driver, WAIT_SEC)

    user_ids = ["Ecom_User_ID", "Ecom_UserID", "Ecom_Username", "username", "user"]
    pid_ids = ["Ecom_Taz", "Ecom_User_Pid", "Ecom_Pid", "pid", "tz"]
    pass_ids = ["Ecom_Password", "Ecom_Pass", "password", "pass"]

    def any_visible_login_field_present(d):
        return (_find_visible(d, By.ID, user_ids) is not None) or (_find_visible(d, By.ID, pass_ids) is not None)

    try:
        wait.until(any_visible_login_field_present)
    except Exception:
        return

    user_field = _find_visible(driver, By.ID, user_ids)
    if user_field:
        _safe_fill(driver, user_field, USERNAME)

    pid_field = _find_visible(driver, By.ID, pid_ids)
    if pid_field:
        _safe_fill(driver, pid_field, USER_ID)

    pass_field = _find_visible(driver, By.ID, pass_ids)
    if not pass_field:
        return

    _safe_fill(driver, pass_field, PASSWORD)

    # נסה קודם כפתור "כניסה"
    clicked = _click_first_xpath(
        driver,
        [
            "//button[contains(normalize-space(.), 'כניסה')]",
            "//input[@type='submit']",
            "//button[@type='submit']",
            "//a[contains(normalize-space(.), 'כניסה')]",
        ],
    )
    if not clicked:
        pass_field.send_keys(Keys.RETURN)

    _sleep_small(1.2)
    handle_saml_post_form_if_present(driver)


def open_moodle_and_start_login(driver: webdriver.Chrome) -> None:
    """
    ה-flow המדויק שביקשת:
    1) /local/mycourses/
    2) קליק על "התחבר/י"
    3) NIDP
    """
    candidates = [
        MY_COURSES_URL,
        MOODLE_LOGIN_INDEX_URL,
        MOODLE_SAML_LOGIN_URL,
    ]

    for idx, url in enumerate(candidates, start=1):
        driver.get(url)
        _wait_body(driver)
        _sleep_small()

        if _is_nidp_login_page(driver):
            print(f"DEBUG candidate {idx}: reached NIDP directly from {url}")
            return

        if _is_moodle_logged_in_page(driver):
            print(f"DEBUG candidate {idx}: already logged in on {url}")
            return

        if idx == 1:
            # /local/mycourses/ -> קליק על התחבר/י
            clicked = _click_first_css(
                driver,
                [
                    "div.usermenu span.login a[href*='/login/index.php']",
                    "a[href='https://moodle.tau.ac.il/login/index.php']",
                    "a[href*='moodle.tau.ac.il/login/index.php']",
                    "a[href*='/login/index.php']",
                ],
            )
            if not clicked:
                clicked = _click_first_xpath(
                    driver,
                    [
                        "//a[contains(normalize-space(.), 'התחבר/י')]",
                        "//a[contains(normalize-space(.), 'התחבר')]",
                        "//a[contains(normalize-space(.), 'Login')]",
                        "//a[contains(normalize-space(.), 'Sign in')]",
                    ],
                )

            if clicked:
                _sleep_small(1.2)
                _wait_body(driver)
                _sleep_small()

                if _is_nidp_login_page(driver):
                    return

                # לפעמים נוחתים קודם ב-login/index.php ואז צריך לבחור SAML
                clicked_saml = _click_first_css(
                    driver,
                    [
                        "a[href*='/auth/saml2/login.php']",
                        "a[href*='nidp.tau.ac.il']",
                    ],
                )
                if not clicked_saml:
                    clicked_saml = _click_first_xpath(
                        driver,
                        [
                            "//a[contains(@href, '/auth/saml2/login.php')]",
                            "//a[contains(@href, 'nidp.tau.ac.il')]",
                            "//a[contains(normalize-space(.), 'אוניברסיטאית')]",
                            "//a[contains(normalize-space(.), 'TAU')]",
                        ],
                    )

                if clicked_saml:
                    _sleep_small(1.2)
                    _wait_body(driver)
                    _sleep_small()
                    if _is_nidp_login_page(driver):
                        return

        # fallback: בדף login index נסה קליק על SAML
        clicked_saml = _click_first_css(
            driver,
            [
                "a[href*='/auth/saml2/login.php']",
                "a[href*='nidp.tau.ac.il']",
            ],
        )
        if not clicked_saml:
            clicked_saml = _click_first_xpath(
                driver,
                [
                    "//a[contains(@href, '/auth/saml2/login.php')]",
                    "//a[contains(@href, 'nidp.tau.ac.il')]",
                    "//a[contains(normalize-space(.), 'אוניברסיטאית')]",
                    "//a[contains(normalize-space(.), 'TAU')]",
                    "//button[contains(normalize-space(.), 'TAU')]",
                ],
            )
        if clicked_saml:
            _sleep_small(1.2)
            _wait_body(driver)
            _sleep_small()
            if _is_nidp_login_page(driver):
                return

    # fallback אחרון
    driver.get(LOGIN_URL)
    _wait_body(driver)
    _sleep_small()


def wait_for_moodle_session(driver: webdriver.Chrome) -> None:
    """
    אחרי NIDP - מוודא שה-session של Moodle נוצר באמת.
    """
    started = time.time()
    recovery_done = False

    while time.time() - started < MAX_SESSION_WAIT_SEC:
        _sleep_small(1.0)

        if handle_saml_post_form_if_present(driver):
            continue

        if _is_moodle_logged_in_page(driver):
            print("DEBUG Moodle session established.")
            return

        cur = _current_url(driver).lower()

        # חזרה ל-NIDP login page -> כנראה משהו לא עבר
        if _is_nidp_login_page(driver):
            # אם עדיין טופס NIDP נראה, ננסה שוב לשלוח
            maybe_login_nidp(driver)
            continue

        # אם אנחנו ב-auth/saml2/login.php או דף חסימה של Moodle, ננסה recovery פעם אחת
        if ("moodle.tau.ac.il" in cur and _is_tau_block_page(driver)) or ("auth/saml2/login.php" in cur):
            if not recovery_done:
                recovery_done = True
                print("DEBUG recovery: trying Moodle login index again after NIDP...")
                driver.get(MOODLE_LOGIN_INDEX_URL)
                _wait_body(driver)
                _sleep_small(1.2)

                if _is_moodle_logged_in_page(driver):
                    return

                if _is_nidp_login_page(driver):
                    maybe_login_nidp(driver)
                    continue

                # נסה לעבור שוב ל-SAML דרך Moodle
                clicked = _click_first_css(driver, ["a[href*='/auth/saml2/login.php']", "a[href*='nidp.tau.ac.il']"])
                if not clicked:
                    clicked = _click_first_xpath(
                        driver,
                        [
                            "//a[contains(@href, '/auth/saml2/login.php')]",
                            "//a[contains(@href, 'nidp.tau.ac.il')]",
                            "//a[contains(normalize-space(.), 'אוניברסיטאית')]",
                            "//a[contains(normalize-space(.), 'TAU')]",
                        ],
                    )
                if clicked:
                    _sleep_small(1.2)
                    if _is_nidp_login_page(driver):
                        maybe_login_nidp(driver)
                        continue

            # אחרי recovery אחד - ממשיכים להמתין עוד קצת
            continue

        # נסה לקפוץ ל-mycourses שוב אם session כבר קיימת אבל לא נחתנו נכון
        if "moodle.tau.ac.il" in cur:
            driver.get(MY_COURSES_URL)
            _wait_body(driver)
            _sleep_small(1.0)

            if _is_moodle_logged_in_page(driver):
                return

    _debug_dump_page(driver, "debug_no_session_after_nidp")
    raise RuntimeError("NIDP login finished, but Moodle session was not established afterwards.")


def ensure_logged_in_moodle(driver: webdriver.Chrome) -> None:
    last_error = None

    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        try:
            print(f"DEBUG login attempt {attempt}/{MAX_LOGIN_ATTEMPTS}")

            driver.get("about:blank")
            _sleep_small(0.3)

            open_moodle_and_start_login(driver)

            if _is_moodle_logged_in_page(driver):
                driver.get(MY_COURSES_URL)
                _wait_body(driver)
                _sleep_small()
                return

            if not _is_nidp_login_page(driver):
                # אולי כבר בעמוד Moodle כלשהו
                driver.get(MOODLE_LOGIN_INDEX_URL)
                _wait_body(driver)
                _sleep_small()

                if not _is_nidp_login_page(driver):
                    clicked = _click_first_css(driver, ["a[href*='/auth/saml2/login.php']", "a[href*='nidp.tau.ac.il']"])
                    if not clicked:
                        clicked = _click_first_xpath(
                            driver,
                            [
                                "//a[contains(@href, '/auth/saml2/login.php')]",
                                "//a[contains(@href, 'nidp.tau.ac.il')]",
                                "//a[contains(normalize-space(.), 'אוניברסיטאית')]",
                                "//a[contains(normalize-space(.), 'TAU')]",
                            ],
                        )
                    _sleep_small(1.0)

            if not _is_nidp_login_page(driver):
                _debug_dump_page(driver, "debug_before_nidp_fill")
                raise RuntimeError("Could not reach NIDP login page from Moodle login flow.")

            maybe_login_nidp(driver)
            wait_for_moodle_session(driver)

            driver.get(MY_COURSES_URL)
            _wait_body(driver)
            _sleep_small()

            if _is_moodle_logged_in_page(driver):
                return

            if _is_tau_block_page(driver):
                raise RuntimeError("Moodle returned block page after successful-looking login.")

            return

        except Exception as e:
            last_error = e
            print(f"DEBUG login attempt failed: {e}")
            if attempt < MAX_LOGIN_ATTEMPTS:
                try:
                    driver.delete_all_cookies()
                except Exception:
                    pass
                _sleep_small(2.0)
            else:
                raise

    if last_error:
        raise last_error


# ==========================
# COURSE RETRIEVAL
# ==========================

def _collect_courses_from_html(html: str) -> list[tuple[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    found = []

    for a in soup.select("a[href*='/course/view.php?id=']"):
        href = a.get("href") or ""
        name = (a.get_text(" ", strip=True) or "").strip()
        if href and "course/view.php?id=" in href:
            found.append((name or href, href))

    uniq = []
    seen = set()
    for n, u in found:
        if u not in seen:
            uniq.append((n, u))
            seen.add(u)
    return uniq


def _collect_courses_via_ajax(session: requests.Session, sesskey: str) -> list[tuple[str, str]]:
    if not sesskey:
        return []

    url = f"{MOODLE_ROOT_URL}lib/ajax/service.php?sesskey={sesskey}&info=block_mycourses_get_enrolled_courses_by_timeline_classification}"

    classifications = [
        "firstsemester",
        "secondsemester",
        "inprogress",
        "future",
        "all",
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

        # parsing גמיש כי המבנה יכול להשתנות
        def walk(obj):
            if isinstance(obj, dict):
                href = ""
                name = ""

                for key in ("viewurl", "courseurl", "url", "link"):
                    if isinstance(obj.get(key), str) and "course/view.php?id=" in obj[key]:
                        href = obj[key]
                        break

                for key in ("displayname", "fullname", "shortname", "name"):
                    if isinstance(obj.get(key), str) and obj[key].strip():
                        name = obj[key].strip()
                        break

                if href:
                    if href not in seen:
                        out.append((name or href, href))
                        seen.add(href)

                for v in obj.values():
                    walk(v)

            elif isinstance(obj, list):
                for item in obj:
                    walk(item)

        walk(data)

    return out


def get_courses(driver: webdriver.Chrome) -> list[tuple[str, str]]:
    ensure_logged_in_moodle(driver)

    driver.get(MY_COURSES_URL)
    _wait_body(driver)
    _sleep_small()

    if _is_tau_block_page(driver):
        _debug_dump_page(driver, "debug_blocked_after_login")
        raise RuntimeError("Blocked page returned even after Moodle login seemed complete.")

    html = _page_source(driver)
    courses = _collect_courses_from_html(html)

    sesskey = _extract_sesskey_from_html(html)
    if not sesskey:
        try:
            session = _session_from_selenium_cookies(driver)
            alt_html = _http_get_html(session, MY_COURSES_URL) or ""
            if alt_html:
                sesskey = _extract_sesskey_from_html(alt_html)
                if not courses:
                    courses = _collect_courses_from_html(alt_html)
        except Exception:
            pass

    if sesskey:
        session = _session_from_selenium_cookies(driver)
        ajax_courses = _collect_courses_via_ajax(session, sesskey)
        all_courses = []
        seen = set()

        for n, u in courses + ajax_courses:
            if u not in seen:
                all_courses.append((n, u))
                seen.add(u)
        courses = all_courses

    print(f"DEBUG collected {len(courses)} courses")
    for idx, (n, u) in enumerate(courses[:20], start=1):
        print(f"DEBUG course {idx}: {n} -> {u}")

    if not courses:
        _debug_dump_page(driver, "debug_no_courses")
        raise RuntimeError("No course links were found after successful Moodle login.")

    return courses


# ==========================
# SCAN
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
        _stop_xvfb()


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
