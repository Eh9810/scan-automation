# -*- coding: utf-8 -*-
"""
export_cookies.py
=================
כלי מקומי – מייצא את עוגיות ה-TAU שנלכדו על ידי debug_browser_capture.py
לפורמט מתאים להזרקה ל-GitHub Actions דרך ה-Secret: MOODLE_INJECTED_COOKIES.

הרצה (לאחר debug_browser_capture.py):
  python export_cookies.py

מה הסקריפט עושה:
  1. מאתר את תיקיית waf_debug_* האחרונה בנתיב התוצאות.
  2. טוען את cookies.json שנלכד על ידי debug_browser_capture.py.
  3. מסנן ושומר רק את העוגיות הרלוונטיות ל-TAU:
       • עוגיות TS*  (F5 BIG-IP trust tokens – המפתח לעקיפת חומת האש)
       • MoodleSession* (סשן מודל)
       • MDL_SSP_AuthToken, JSESSIONID (SSO tokens)
       • כל עוגיה אחרת מדומיין tau.ac.il
  4. מדפיס JSON דחוס שניתן להדביק ישירות כ-GitHub Secret.

הוראות לאחר הרצה:
  1. העתיקי את ה-JSON שמודפס.
  2. ב-GitHub → Settings → Secrets and variables → Actions → New repository secret:
       Name:  MOODLE_INJECTED_COOKIES
       Value: (הדביקי כאן את ה-JSON)
  3. הפעילי ידנית את ה-workflow (Run workflow) → GitHub Actions ישתמש בעוגיות.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── same default path used by debug_browser_capture.py ───────────────────────
_DEFAULT_RESULTS_BASE = Path(
    r"C:\Users\edeni\OneDrive\PythonStudies\python uses"
    r"\extract_files_from_moodle\understanding how moodle security works"
    r"\results\GITHUB"
)
RESULTS_BASE = Path(os.environ.get("WAF_RESULTS_DIR", "") or _DEFAULT_RESULTS_BASE)
TZ_IL = timezone(timedelta(hours=3))

# Domains considered relevant to TAU Moodle
_TAU_DOMAINS = ("tau.ac.il",)

# Default domain when a CDP cookie object has no explicit domain field.
_DEFAULT_MOODLE_DOMAIN = "moodle.tau.ac.il"

# Cookie names that are especially critical for bypassing the F5 WAF.
# TS* cookies are F5 BIG-IP bot-score trust tokens – without them the WAF
# assigns a high bot score to GitHub-hosted runner IPs and blocks the request.
_CRITICAL_PREFIXES = ("TS",)
_CRITICAL_NAMES = {
    "MoodleSession",
    "MDL_SSP_AuthToken",
    "JSESSIONID",
    "MoodleSessionMoodle2025",
}


def _is_tau_cookie(c: dict) -> bool:
    domain = (c.get("domain") or c.get("Domain") or "").lstrip(".")
    return any(d in domain for d in _TAU_DOMAINS)


def _is_critical(c: dict) -> bool:
    name = c.get("name") or c.get("Name") or ""
    if any(name.startswith(p) for p in _CRITICAL_PREFIXES):
        return True
    # prefix-match for versioned names like MoodleSessionMoodle2025
    return any(name.startswith(n) for n in _CRITICAL_NAMES)


def _find_debug_folders() -> list[Path]:
    if not RESULTS_BASE.exists():
        return []
    return sorted(
        [p for p in RESULTS_BASE.iterdir() if p.is_dir() and p.name.startswith("waf_debug_")],
        key=lambda p: p.name,
        reverse=True,
    )


def _pick_folder(folders: list[Path]) -> Path:
    if not folders:
        sys.exit(
            f"\n❌  לא נמצאה תיקיית waf_debug_* ב:\n   {RESULTS_BASE}\n\n"
            "הרץ קודם את debug_browser_capture.py ואז הרץ סקריפט זה."
        )
    if len(folders) == 1:
        return folders[0]
    print("\nנמצאו מספר תיקיות תוצאות. בחרי מספר:\n")
    for i, f in enumerate(folders, 1):
        ts = f.name[len("waf_debug_"):]
        print(f"  {i}. {f.name}  ({ts})")
    print()
    while True:
        try:
            choice = int(input(f"הכניסי מספר (1-{len(folders)}): ").strip())
            if 1 <= choice <= len(folders):
                return folders[choice - 1]
        except (ValueError, KeyboardInterrupt):
            pass
        print("בחירה לא תקינה – נסי שוב.")


def _load_cookies(folder: Path) -> list[dict]:
    """
    Load cookies from `folder/cookies.json`.

    The file is produced by debug_browser_capture.py via the Chrome DevTools
    Protocol (CDP) Network.getAllCookies.  Each entry is a CDP cookie object
    (keys: name, value, domain, path, expires, size, httpOnly, secure,
    session, sameSite, priority, ...).

    Returns the raw list; the caller handles filtering.
    """
    cookies_path = folder / "cookies.json"
    if not cookies_path.exists():
        # Also try network_log.json or storage.json as fallback sources
        for alt in ("storage.json",):
            alt_path = folder / alt
            if alt_path.exists():
                try:
                    data = json.loads(alt_path.read_text(encoding="utf-8"))
                    # storage.json may have a "cookies" key
                    if isinstance(data, dict) and "cookies" in data:
                        raw = data["cookies"]
                        if isinstance(raw, list):
                            return raw
                except Exception:
                    pass
        sys.exit(
            f"\n❌  לא נמצא קובץ cookies.json בתיקייה:\n   {folder}\n\n"
            "ודאי שהרצת את debug_browser_capture.py וגלשת לאתר לפני הסגירה."
        )
    try:
        raw = json.loads(cookies_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        sys.exit(f"\n❌  שגיאה בקריאת cookies.json: {exc}")

    if not isinstance(raw, list):
        # Some older versions wrapped the list in a dict
        if isinstance(raw, dict) and "cookies" in raw:
            raw = raw["cookies"]
        else:
            sys.exit(f"\n❌  cookies.json לא במבנה הצפוי (רשימה).")

    return raw


def _normalise(c: dict) -> dict:
    """Return a minimal cookie dict with only the fields requests.Session needs."""
    name = c.get("name") or c.get("Name") or ""
    value = c.get("value") if c.get("value") is not None else c.get("Value", "")
    domain = (c.get("domain") or c.get("Domain") or _DEFAULT_MOODLE_DOMAIN).lstrip(".")
    path = c.get("path") or c.get("Path") or "/"
    return {"name": name, "value": str(value), "domain": domain, "path": path}


def main() -> None:
    print("=" * 70)
    print("TAU Moodle WAF Bypass – Cookie Export for GitHub Actions")
    print("=" * 70)

    folders = _find_debug_folders()
    folder = _pick_folder(folders)
    print(f"\nתיקייה שנבחרה: {folder.name}")

    raw_cookies = _load_cookies(folder)
    print(f"סה\"כ עוגיות שנלכדו: {len(raw_cookies)}")

    # ── Filter to TAU-relevant cookies ───────────────────────────────────────
    tau_cookies = [c for c in raw_cookies if _is_tau_cookie(c)]
    critical = [c for c in tau_cookies if _is_critical(c)]
    other_tau = [c for c in tau_cookies if not _is_critical(c)]

    print(f"\nעוגיות TAU שנמצאו: {len(tau_cookies)}")
    print(f"  קריטיות (F5 TS* + Moodle session + SSO): {len(critical)}")
    print(f"  אחרות (tau.ac.il):                       {len(other_tau)}")

    if not tau_cookies:
        print(
            "\n⚠️  לא נמצאו עוגיות TAU.\n"
            "ודאי שהתחברת לאתר מודל בזמן ריצת debug_browser_capture.py."
        )
        sys.exit(1)

    # Prefer critical cookies; include all TAU cookies for completeness
    ordered = critical + other_tau
    normalised = [_normalise(c) for c in ordered if c.get("name") or c.get("Name")]

    ts_cookies = [c for c in normalised if c["name"].startswith("TS")]
    moodle_session = [c for c in normalised if c["name"].startswith("MoodleSession")]
    sso_cookies = [c for c in normalised if c["name"] in ("MDL_SSP_AuthToken", "JSESSIONID")]

    print("\n── עוגיות F5 BIG-IP (TS*) שנמצאו ─────────────────────────────────")
    if ts_cookies:
        for c in ts_cookies:
            print(f"  ✅  {c['name']}  (domain: {c['domain']})")
    else:
        print("  ⚠️  אין עוגיות TS* – ייתכן שהסשן נוצר לפני שה-WAF הגיב")

    print("\n── עוגיות סשן מודל ─────────────────────────────────────────────────")
    if moodle_session:
        for c in moodle_session:
            print(f"  ✅  {c['name']}  (domain: {c['domain']})")
    else:
        print("  ⚠️  אין MoodleSession* – התחברות חלקית בלבד")

    print("\n── עוגיות SSO ──────────────────────────────────────────────────────")
    if sso_cookies:
        for c in sso_cookies:
            print(f"  ✅  {c['name']}  (domain: {c['domain']})")
    else:
        print("  (לא נמצאו)")

    # ── Encode to compact JSON ────────────────────────────────────────────────
    secret_value = json.dumps(normalised, ensure_ascii=False, separators=(",", ":"))
    secret_size_kb = len(secret_value.encode()) / 1024

    print(f"\n{'=' * 70}")
    print(f"📋  ערך ה-Secret (העתיקי את כל השורה – {secret_size_kb:.1f} KB):")
    print("=" * 70)
    print(secret_value)
    print("=" * 70)

    # ── Save to file as well ──────────────────────────────────────────────────
    out_path = folder / "github_secret_MOODLE_INJECTED_COOKIES.txt"
    out_path.write_text(secret_value, encoding="utf-8")

    print(f"\n✅  הקובץ נשמר גם ב:\n   {out_path}")
    print(
        f"\n{'=' * 70}\n"
        "📌  הוראות הדבקה ב-GitHub:\n"
        "  1. פתחי: https://github.com/Eh9810/scan-automation/settings/secrets/actions\n"
        "  2. לחצי 'New repository secret' (או ערכי את הקיים):\n"
        "       Name:  MOODLE_INJECTED_COOKIES\n"
        "       Value: (הדביקי את ה-JSON שמעל)\n"
        "  3. שמרי → לחצי 'Run workflow' כדי לבדוק.\n"
        f"{'=' * 70}\n"
        "💡  תוקף העוגיות: בדרך כלל 2-24 שעות.\n"
        "    אם ה-workflow נכשל שוב לאחר יום – חזרי על התהליך מ-debug_browser_capture.py.\n"
        "    לאחר הזרקה מוצלחת, ה-workflow שומר את הסשן ב-cache ומשתמש בו אוטומטית.\n"
        f"{'=' * 70}"
    )


if __name__ == "__main__":
    main()
