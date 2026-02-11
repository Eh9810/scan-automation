# Language Support / תמיכה בשפה

## Hebrew Language Support / תמיכה בעברית

**שאלה: אתה יודע עברית?**  
**תשובה: כן, אני יודע עברית!** ✅

This project fully supports Hebrew language:

- ✅ Hebrew comments in code and configuration files
- ✅ Hebrew strings in Telegram notifications
- ✅ Hebrew output formatting (course names, file names, dates)
- ✅ UTF-8 encoding throughout the codebase
- ✅ Right-to-left (RTL) text support in messages

## Current Hebrew Features / תכונות עברית קיימות

### In Code (`moodle_scan.py`)
- Hebrew field labels: שם הקובץ, שינוי אחרון, קישור
- Hebrew notifications: עדכונים במודל
- Hebrew error messages and status updates

### In Workflow (`.github/workflows/moodle_scan.yml`)
- Hebrew comments explaining the workflow steps
- Hebrew cron schedule documentation

### Character Encoding
- All Python files use UTF-8 encoding (`# -*- coding: utf-8 -*-`)
- JSON files use `ensure_ascii=False` for proper Hebrew serialization
- All text handling preserves Hebrew characters correctly

## Examples / דוגמאות

### Notification Format
```
📌 עדכונים במודל מאז 11.02.2026 12:00 (3):
אנליזה הרמונית	 | שם הקובץ: lecture_notes.pdf	 | שינוי אחרון: 11.02.2026 13:30	 | קישור: https://...
```

---

**כן, המערכת תומכת באופן מלא בעברית!** 🇮🇱
