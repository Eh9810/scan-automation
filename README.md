# scan-automation

## Local forensic collector (manual login)

If GitHub Actions is blocked by TAU/WAF and you want maximum browser-side evidence from a local machine, run:

```bash
python local_debug_capture.py
```

This opens visible Chrome, lets you log in manually, and writes snapshots/logs/cookies/storage/performance logs to:

`C:\Users\edeni\OneDrive\PythonStudies\python uses\extract_files_from_moodle\understanding how moodle security works\results\CODEX\capture_<timestamp>\`

Includes `summary.json` with support IDs, blocked markers, exact URL/title/time (Asia/Jerusalem).

### Optional: run scanner using pre-approved local session cookies

If TAU WAF blocks GitHub IP ranges, you can export cookies from your local successful session and pass them as a secret:

1. From local forensic output, take `cookies.json`.
2. Base64 encode it and save as GitHub secret `MOODLE_COOKIE_SEED_B64`.
3. Workflow will inject these cookies before login flow.

> Note: this does **not** guarantee bypass (cookies may expire quickly), but it helps validate whether session seeding can pass WAF-sensitive stages.
