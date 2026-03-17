# scan-automation

## Local forensic collector (manual login)

If GitHub Actions is blocked by TAU/WAF and you want maximum browser-side evidence from a local machine, run:

```bash
python local_debug_capture.py
```

This opens visible Chrome, lets you log in manually, and writes snapshots/logs/cookies/storage/performance logs to:

`forensics_output/capture_<timestamp>/`

Includes `summary.json` with support IDs, blocked markers, exact URL/title/time (Asia/Jerusalem).
