# -*- coding: utf-8 -*-
"""
Local TAU Moodle forensic collector (manual-login mode)

What it does:
- Opens visible Chrome (not headless) so user logs in manually.
- Collects as much client-side evidence as possible while browsing:
  - page HTML snapshots
  - current URL + title
  - browser console logs
  - Chrome performance/CDP logs (network/security related events)
  - cookies
  - localStorage / sessionStorage
  - response headers discovered from performance logs
  - support ID / access-denied / maintenance markers
- Writes everything into a timestamped folder.

Important:
This can provide strong evidence for TAU support, but cannot directly reveal
private server-only rules (e.g. exact WAF rule ID / bot score internals)
unless such fields are exposed in returned headers/pages.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from selenium import webdriver
from selenium.webdriver.chrome.options import Options


TZ_IL = ZoneInfo("Asia/Jerusalem")
BASE_URL = "https://moodle.tau.ac.il/local/mycourses/"
OUT_ROOT = Path("forensics_output")


@dataclass
class PageEvidence:
    ts_il: str
    url: str
    title: str
    support_ids: list[str]
    blocked_markers: list[str]
    response_headers_hint: dict[str, dict[str, str]]


def now_il_str() -> str:
    return datetime.now(TZ_IL).strftime("%Y-%m-%d_%H-%M-%S")


def sanitize_filename(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "_", s)
    return s[:120] or "snapshot"


def build_driver() -> webdriver.Chrome:
    opts = Options()
    opts.add_argument("--disable-popup-blocking")
    opts.add_argument("--disable-notifications")
    opts.add_argument("--window-size=1500,1000")
    opts.add_argument("--lang=he-IL")

    # enable logs
    opts.set_capability("goog:loggingPrefs", {"browser": "ALL", "performance": "ALL"})

    driver = webdriver.Chrome(options=opts)
    return driver


def detect_markers(html: str, title: str) -> tuple[list[str], list[str]]:
    text = f"{title}\n{html}".lower()
    blocked = []
    for m in [
        "access denied",
        "under maintenence",
        "under maintenance",
        "בקשה נדחתה",
        "your support id is",
    ]:
        if m in text:
            blocked.append(m)

    support_ids = re.findall(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        text,
        flags=re.IGNORECASE,
    )
    return sorted(set(blocked)), sorted(set(support_ids))


def extract_network_hints_from_perf_logs(perf_logs: list[dict]) -> dict[str, dict[str, str]]:
    """Best-effort extraction of response headers from CDP performance logs."""
    out: dict[str, dict[str, str]] = {}
    for row in perf_logs:
        try:
            msg = json.loads(row.get("message", "{}"))
            m = msg.get("message", {})
            method = m.get("method")
            params = m.get("params", {})
            if method != "Network.responseReceived":
                continue
            resp = params.get("response", {})
            url = resp.get("url", "")
            headers = resp.get("headers", {}) or {}
            if not url:
                continue

            interesting = {}
            for k, v in headers.items():
                lk = k.lower()
                if lk in {
                    "server",
                    "via",
                    "x-cache",
                    "x-served-by",
                    "x-request-id",
                    "x-correlation-id",
                    "cf-ray",
                    "x-amz-cf-id",
                    "retry-after",
                    "x-rate-limit-limit",
                    "x-rate-limit-remaining",
                    "x-rate-limit-reset",
                    "set-cookie",
                    "location",
                    "content-security-policy",
                }:
                    interesting[k] = str(v)

            if interesting:
                out[url] = interesting
        except Exception:
            continue
    return out


def dump_snapshot(driver: webdriver.Chrome, out_dir: Path, label: str) -> PageEvidence:
    ts = now_il_str()
    url = driver.current_url
    title = driver.title or ""
    html = driver.page_source or ""

    safe = sanitize_filename(label)
    (out_dir / f"{ts}__{safe}.html").write_text(html, encoding="utf-8")

    blocked_markers, support_ids = detect_markers(html, title)

    perf_logs = driver.get_log("performance")
    headers_hint = extract_network_hints_from_perf_logs(perf_logs)
    (out_dir / f"{ts}__{safe}__perf.json").write_text(
        json.dumps(perf_logs, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    return PageEvidence(
        ts_il=ts,
        url=url,
        title=title,
        support_ids=support_ids,
        blocked_markers=blocked_markers,
        response_headers_hint=headers_hint,
    )


def dump_environment(driver: webdriver.Chrome, out_dir: Path) -> None:
    (out_dir / "cookies.json").write_text(
        json.dumps(driver.get_cookies(), ensure_ascii=False, indent=2), encoding="utf-8"
    )

    js = """
    return {
      href: window.location.href,
      userAgent: navigator.userAgent,
      platform: navigator.platform,
      language: navigator.language,
      webdriver: navigator.webdriver,
      localStorage: Object.assign({}, window.localStorage),
      sessionStorage: Object.assign({}, window.sessionStorage)
    };
    """
    env = driver.execute_script(js)
    (out_dir / "browser_env.json").write_text(json.dumps(env, ensure_ascii=False, indent=2), encoding="utf-8")

    try:
        browser_logs = driver.get_log("browser")
    except Exception:
        browser_logs = []
    (out_dir / "browser_console.json").write_text(
        json.dumps(browser_logs, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def main() -> None:
    out_dir = OUT_ROOT / f"capture_{now_il_str()}"
    out_dir.mkdir(parents=True, exist_ok=True)

    driver = build_driver()
    evidences: list[PageEvidence] = []

    try:
        driver.get(BASE_URL)
        print("\n=== Manual forensic mode ===")
        print("1) התחבר/י ידנית באתר בדפדפן שנפתח")
        print("2) עברי בין כמה קורסים/תיקיות רנדומליות")
        print("3) חזרי לכאן והקלידי Enter בכל פעם שאת רוצה Snapshot")
        print("4) הקלידי DONE לסיום\n")

        idx = 1
        while True:
            cmd = input("Enter=take snapshot | DONE=finish > ").strip().lower()
            if cmd == "done":
                break
            label = f"manual_{idx}"
            ev = dump_snapshot(driver, out_dir, label)
            evidences.append(ev)
            print(f"Saved snapshot #{idx}: {ev.url}")
            if ev.support_ids:
                print(f"  Support IDs: {ev.support_ids}")
            if ev.blocked_markers:
                print(f"  Block markers: {ev.blocked_markers}")
            idx += 1

        dump_environment(driver, out_dir)

        summary = {
            "captured_at_il": now_il_str(),
            "notes": [
                "This package is client-side evidence.",
                "Exact internal TAU/WAF rule, bot-score internals, or private firewall policy cannot be proven from browser-side data alone.",
                "Provide Support ID + timestamp + blocked URL to TAU support for server-side correlation.",
            ],
            "evidences": [asdict(e) for e in evidences],
        }
        (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

        print(f"\nDone. Output folder: {out_dir.resolve()}")

    finally:
        driver.quit()


if __name__ == "__main__":
    main()
