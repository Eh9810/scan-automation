def _collect_courses_via_ajax(session: requests.Session, sesskey: str) -> list[tuple[str, str]]:
    if not sesskey:
        return []

    url = (
        f"{MOODLE_ROOT_URL}lib/ajax/service.php"
        f"?sesskey={sesskey}"
        f"&info=block_mycourses_get_enrolled_courses_by_timeline_classification"
    )

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

                if href and href not in seen:
                    out.append((name or href, href))
                    seen.add(href)

                for v in obj.values():
                    walk(v)

            elif isinstance(obj, list):
                for item in obj:
                    walk(item)

        walk(data)

    return out
