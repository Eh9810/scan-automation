# -*- coding: utf-8 -*-
"""
upload_results.py
=================
כלי שליחה – מעלה את תוצאות debug_browser_capture.py ל-GitHub
כך שניתן לנתח אותן מרחוק.

הרצה:
  python upload_results.py

מה הסקריפט עושה:
  1. מאתר את תיקיית waf_debug_* האחרונה (או שואל אותך לבחור).
  2. יוצר zip ממנה.
  3. מעלה אותה ל-branch ייעודי בשם "diagnostic-results" בריפוזיטורי:
       https://github.com/Eh9810/scan-automation
  4. מדפיס קישור ישיר לקבצים ב-GitHub.

דרישות מוקדמות:
  pip install requests
  יצירת GitHub Personal Access Token (PAT) עם הרשאת repo:
    https://github.com/settings/tokens/new?scopes=repo&description=waf-upload

הגדרת ה-PAT (אחת מהאפשרויות):
  • משתנה סביבה:  set GITHUB_PAT=ghp_xxxx    (Windows)
  • או: הסקריפט ישאל אותך בעת ההרצה.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── dependency check ──────────────────────────────────────────────────────────
try:
    import requests
except ImportError:
    sys.exit("Missing: pip install requests")

# ── configuration ─────────────────────────────────────────────────────────────
GITHUB_REPO  = "Eh9810/scan-automation"
UPLOAD_BRANCH = "diagnostic-results"
TZ_IL = timezone(timedelta(hours=3))

# The same base path used by debug_browser_capture.py
_DEFAULT_RESULTS_BASE = Path(
    r"C:\Users\edeni\OneDrive\PythonStudies\python uses"
    r"\extract_files_from_moodle\understanding how moodle security works"
    r"\results\GITHUB"
)

RESULTS_BASE = Path(os.environ.get("WAF_RESULTS_DIR", "") or _DEFAULT_RESULTS_BASE)

GITHUB_API = "https://api.github.com"


# =============================================================================
# GitHub API helpers
# =============================================================================

def _api_headers(token: str) -> dict:
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _get(url: str, token: str) -> dict:
    r = requests.get(url, headers=_api_headers(token), timeout=20)
    r.raise_for_status()
    return r.json()


def _put(url: str, token: str, body: dict) -> dict:
    r = requests.put(url, headers=_api_headers(token), json=body, timeout=30)
    r.raise_for_status()
    return r.json()


def _get_default_branch(token: str) -> str:
    data = _get(f"{GITHUB_API}/repos/{GITHUB_REPO}", token)
    return data["default_branch"]


def _get_branch_sha(branch: str, token: str) -> str | None:
    """Return the HEAD commit SHA of `branch`, or None if it doesn't exist."""
    url = f"{GITHUB_API}/repos/{GITHUB_REPO}/git/ref/heads/{branch}"
    r = requests.get(url, headers=_api_headers(token), timeout=20)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()["object"]["sha"]


def _get_tree_sha(commit_sha: str, token: str) -> str:
    data = _get(f"{GITHUB_API}/repos/{GITHUB_REPO}/git/commits/{commit_sha}", token)
    return data["tree"]["sha"]


def _create_blob(content_bytes: bytes, token: str) -> str:
    """Upload raw bytes as a Git blob; return the blob SHA."""
    body = {
        "content": base64.b64encode(content_bytes).decode(),
        "encoding": "base64",
    }
    data = requests.post(
        f"{GITHUB_API}/repos/{GITHUB_REPO}/git/blobs",
        headers=_api_headers(token),
        json=body,
        timeout=60,
    )
    data.raise_for_status()
    return data.json()["sha"]


def _create_tree(base_tree_sha: str, file_entries: list[dict], token: str) -> str:
    """
    Create a new Git tree that adds all `file_entries` on top of `base_tree_sha`.
    Each entry: {"path": str, "blob_sha": str}
    Returns the new tree SHA.
    """
    tree = [
        {"path": e["path"], "mode": "100644", "type": "blob", "sha": e["blob_sha"]}
        for e in file_entries
    ]
    body = {"base_tree": base_tree_sha, "tree": tree}
    data = requests.post(
        f"{GITHUB_API}/repos/{GITHUB_REPO}/git/trees",
        headers=_api_headers(token),
        json=body,
        timeout=60,
    )
    data.raise_for_status()
    return data.json()["sha"]


def _create_commit(tree_sha: str, parent_sha: str, message: str, token: str) -> str:
    body = {
        "message": message,
        "tree": tree_sha,
        "parents": [parent_sha],
    }
    data = requests.post(
        f"{GITHUB_API}/repos/{GITHUB_REPO}/git/commits",
        headers=_api_headers(token),
        json=body,
        timeout=30,
    )
    data.raise_for_status()
    return data.json()["sha"]


def _update_or_create_branch(branch: str, commit_sha: str, token: str) -> None:
    """Point `branch` to `commit_sha`, creating it if necessary."""
    url = f"{GITHUB_API}/repos/{GITHUB_REPO}/git/refs/heads/{branch}"
    r = requests.get(url, headers=_api_headers(token), timeout=20)
    if r.status_code == 404:
        # Create new branch
        body = {"ref": f"refs/heads/{branch}", "sha": commit_sha}
        requests.post(
            f"{GITHUB_API}/repos/{GITHUB_REPO}/git/refs",
            headers=_api_headers(token),
            json=body,
            timeout=30,
        ).raise_for_status()
    else:
        r.raise_for_status()
        # Force-update existing branch
        requests.patch(
            url,
            headers=_api_headers(token),
            json={"sha": commit_sha, "force": True},
            timeout=30,
        ).raise_for_status()


# =============================================================================
# Folder discovery
# =============================================================================

def _find_debug_folders() -> list[Path]:
    """Return all waf_debug_* folders in RESULTS_BASE, newest first."""
    if not RESULTS_BASE.exists():
        return []
    folders = sorted(
        [p for p in RESULTS_BASE.iterdir() if p.is_dir() and p.name.startswith("waf_debug_")],
        key=lambda p: p.name,
        reverse=True,
    )
    return folders


def _pick_folder(folders: list[Path]) -> Path:
    """Ask user to pick a folder if there are multiple; auto-pick if only one."""
    if not folders:
        sys.exit(
            f"\n❌  לא נמצאה תיקיית waf_debug_* ב:\n   {RESULTS_BASE}\n\n"
            "הרץ קודם את debug_browser_capture.py ואז הרץ סקריפט זה."
        )
    if len(folders) == 1:
        print(f"✅  נמצאה תיקייה אחת: {folders[0].name}")
        return folders[0]

    print("\nנמצאו מספר תיקיות תוצאות. בחרי מספר:\n")
    for i, f in enumerate(folders, 1):
        print(f"  {i}. {f.name}")
    print()
    while True:
        try:
            choice = int(input(f"הכניסי מספר (1-{len(folders)}): ").strip())
            if 1 <= choice <= len(folders):
                return folders[choice - 1]
        except (ValueError, KeyboardInterrupt):
            pass
        print("בחירה לא תקינה – נסי שוב.")


# =============================================================================
# Zip helpers
# =============================================================================

def _zip_folder(folder: Path) -> tuple[Path, list[tuple[str, bytes]]]:
    """
    Zip all files in `folder` and return:
      (zip_path, [(relative_path_str, file_bytes), ...])
    The zip is written next to the folder.
    """
    zip_path = folder.parent / (folder.name + ".zip")
    entries: list[tuple[str, bytes]] = []

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(folder.rglob("*")):
            if file_path.is_file():
                rel = file_path.relative_to(folder.parent)
                zf.write(file_path, arcname=str(rel))
                entries.append((str(rel).replace("\\", "/"), file_path.read_bytes()))

    return zip_path, entries


# =============================================================================
# Upload
# =============================================================================

_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB hard cap per file (GitHub API limit)
_SKIP_EXTENSIONS = {".zip"}        # don't re-upload the zip we just created


def _collect_upload_entries(folder: Path, zip_path: Path) -> list[dict]:
    """
    Build the list of files to upload.
    Individual files that are too large are replaced by a placeholder note.
    The zip archive of the whole folder is always included.
    """
    entries: list[dict] = []
    prefix = folder.name  # all paths go inside a sub-folder named after the run

    # ── individual files ──
    for file_path in sorted(folder.rglob("*")):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() in _SKIP_EXTENSIONS:
            continue
        rel = file_path.relative_to(folder)
        gh_path = f"{prefix}/{str(rel).replace(chr(92), '/')}"
        size = file_path.stat().st_size
        if size > _MAX_FILE_SIZE:
            # too large for the API – upload a placeholder
            note = (
                f"[File too large to upload via API: {file_path.name}, {size:,} bytes]\n"
                "See the .zip archive in this folder for the full content."
            )
            entries.append({"path": gh_path, "content": note.encode()})
        else:
            entries.append({"path": gh_path, "content": file_path.read_bytes()})

    # ── full zip ──
    zip_size = zip_path.stat().st_size
    if zip_size <= _MAX_FILE_SIZE:
        entries.append({
            "path": f"{zip_path.name}",
            "content": zip_path.read_bytes(),
        })
    else:
        note = (
            f"[Zip archive too large for GitHub API: {zip_path.name}, {zip_size:,} bytes]\n"
            "Please upload the zip manually or split it."
        )
        entries.append({"path": zip_path.name, "content": note.encode()})

    return entries


def upload_folder(folder: Path, token: str) -> str:
    """
    Upload all files in `folder` to UPLOAD_BRANCH and return the GitHub URL
    for the uploaded run folder.
    """
    print(f"\n📦  Creating zip of {folder.name} …")
    zip_path, _ = _zip_folder(folder)
    print(f"    Zip: {zip_path.name}  ({zip_path.stat().st_size:,} bytes)")

    entries = _collect_upload_entries(folder, zip_path)
    print(f"    Files to upload: {len(entries)}")

    # ── get base commit SHA ──
    print(f"\n🔗  Connecting to GitHub → {GITHUB_REPO} …")
    default_branch = _get_default_branch(token)
    base_sha = _get_branch_sha(UPLOAD_BRANCH, token)
    if base_sha is None:
        print(f"    Branch '{UPLOAD_BRANCH}' does not exist – will create it.")
        base_sha = _get_branch_sha(default_branch, token)
        if base_sha is None:
            sys.exit(f"❌  Could not find branch '{default_branch}' on {GITHUB_REPO}")

    base_tree_sha = _get_tree_sha(base_sha, token)

    # ── upload blobs ──
    print(f"\n⬆️   Uploading {len(entries)} file(s) …")
    blob_entries: list[dict] = []
    for i, e in enumerate(entries, 1):
        size_kb = len(e["content"]) / 1024
        print(f"    [{i}/{len(entries)}] {e['path']}  ({size_kb:.1f} KB)")
        blob_sha = _create_blob(e["content"], token)
        blob_entries.append({"path": e["path"], "blob_sha": blob_sha})

    # ── commit ──
    ts_il = datetime.now(TZ_IL).strftime("%Y-%m-%d %H:%M:%S %Z")
    commit_msg = (
        f"diagnostic: upload {folder.name}\n\n"
        f"Uploaded at {ts_il} from debug_browser_capture.py\n"
        f"Repo: {GITHUB_REPO}  Branch: {UPLOAD_BRANCH}"
    )
    new_tree_sha = _create_tree(base_tree_sha, blob_entries, token)
    new_commit_sha = _create_commit(new_tree_sha, base_sha, commit_msg, token)
    _update_or_create_branch(UPLOAD_BRANCH, new_commit_sha, token)

    # ── build URL ──
    folder_url = (
        f"https://github.com/{GITHUB_REPO}/tree/{UPLOAD_BRANCH}/{folder.name}"
    )
    zip_url = (
        f"https://github.com/{GITHUB_REPO}/blob/{UPLOAD_BRANCH}/{zip_path.name}"
    )
    return folder_url, zip_url


# =============================================================================
# Main
# =============================================================================

def main() -> None:
    print("=" * 70)
    print("TAU Moodle WAF Diagnostic – Upload to GitHub")
    print("=" * 70)

    # ── find output folder ──
    folders = _find_debug_folders()
    folder = _pick_folder(folders)
    print(f"\nתיקייה שנבחרה: {folder}")

    # ── get GitHub token ──
    token = os.environ.get("GITHUB_PAT", "").strip()
    if not token:
        print(
            "\nנדרש GitHub Personal Access Token (PAT) עם הרשאת 'repo'.\n"
            "יצירת טוקן: https://github.com/settings/tokens/new?scopes=repo&description=waf-upload\n"
        )
        try:
            token = input("הכניסי את ה-PAT שלך: ").strip()
        except KeyboardInterrupt:
            sys.exit("\nבוטל.")
    if not token:
        sys.exit("❌  לא סופק PAT – יציאה.")

    # ── upload ──
    try:
        folder_url, zip_url = upload_folder(folder, token)
    except requests.HTTPError as exc:
        sys.exit(f"\n❌  GitHub API error: {exc}\n{exc.response.text[:500]}")

    print(f"\n{'=' * 70}")
    print("✅  העלאה הצליחה!")
    print(f"\n📂  קישור לתיקייה ב-GitHub:\n    {folder_url}")
    print(f"\n📦  קישור ל-zip:\n    {zip_url}")
    print(
        f"\n💡  כדי לשתף עם המפתח – שלחי את הקישור:\n    {folder_url}"
    )
    print("=" * 70)


if __name__ == "__main__":
    main()
