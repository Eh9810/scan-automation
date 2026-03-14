 (cd "$(git rev-parse --show-toplevel)" && git apply --3way <<'EOF' 
diff --git a/moodle_scan.py b/moodle_scan.py
index 7bb84071538967e5b360bea6bc28e31085026b99..4b11d911870853c88f22e12c5458cf40dfbeb20b 100644
--- a/moodle_scan.py
+++ b/moodle_scan.py
@@ -433,89 +433,118 @@ def click_login_if_guest(driver: webdriver.Chrome) -> bool:
         "a[href='https://moodle.tau.ac.il/login/index.php']",
         "a[href*='moodle.tau.ac.il/login/index.php']",
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
         els = driver.find_elements(By.XPATH, "//a[contains(normalize-space(.), 'התחבר')]")
         for el in els:
             if el.is_displayed():
                 driver.execute_script("arguments[0].click();", el)
                 return True
     except Exception:
         pass
 
     return False
 
 
+def _collect_course_anchors(driver: webdriver.Chrome):
+    """
+    Collect visible anchors that look like Moodle course links.
+    Keep this broad to survive markup/class changes in MyCourses pages.
+    """
+    candidates = driver.find_elements(By.CSS_SELECTOR, "a[href*='course/view.php?id=']")
+    visible = []
+    for el in candidates:
+        try:
+            if el.is_displayed():
+                visible.append(el)
+        except Exception:
+            continue
+    return visible
+
+
 def ensure_logged_in_moodle(driver: webdriver.Chrome) -> None:
     """
     Go to MyCourses.
     If guest access -> click login -> complete SSO -> back to MyCourses.
     """
     wait = WebDriverWait(driver, WAIT_SEC)
     driver.get(MY_COURSES_URL)
     wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
     time.sleep(0.8)
 
     if click_login_if_guest(driver):
         time.sleep(1.2)
 
         if "nidp.tau.ac.il" in driver.current_url.lower():
             maybe_login_nidp(driver)
             ensure_on_moodle(driver)
 
         driver.get(MY_COURSES_URL)
 
     def courses_or_guest(d):
-        if d.find_elements(By.CSS_SELECTOR, "a.mycourses_coursename"):
+        if _collect_course_anchors(d):
             return True
         if d.find_elements(By.XPATH, "//*[contains(., 'גישת אורחים')]"):
             return True
+        if d.find_elements(By.CSS_SELECTOR, "a[href*='/login/index.php']"):
+            return True
         return False
 
-    wait.until(courses_or_guest)
+    try:
+        wait.until(courses_or_guest)
+    except Exception:
+        # Fallback: if Moodle bounced us back to a login page, retry once through SSO.
+        if driver.find_elements(By.CSS_SELECTOR, "a[href*='/login/index.php']") or "login" in driver.current_url.lower():
+            driver.get(LOGIN_URL)
+            maybe_login_nidp(driver)
+            ensure_on_moodle(driver)
+            driver.get(MY_COURSES_URL)
+            wait.until(courses_or_guest)
+        else:
+            raise
 
     if driver.find_elements(By.XPATH, "//*[contains(., 'גישת אורחים')]"):
         raise RuntimeError("Still guest access on MyCourses; SSO did not complete automatically.")
 
 
 def get_courses(driver: webdriver.Chrome) -> list[tuple[str, str]]:
     ensure_logged_in_moodle(driver)
 
     wait = WebDriverWait(driver, WAIT_SEC)
-    wait.until(EC.presence_of_all_elements_located((By.CSS_SELECTOR, "a.mycourses_coursename")))
+    wait.until(lambda d: len(_collect_course_anchors(d)) > 0)
 
-    links = driver.find_elements(By.CSS_SELECTOR, "a.mycourses_coursename")
+    links = _collect_course_anchors(driver)
     courses: list[tuple[str, str]] = []
     for a in links:
         name = (a.text or "").strip()
         href = a.get_attribute("href")
         if name and href and "course/view.php?id=" in href:
             courses.append((name, href))
 
     uniq: list[tuple[str, str]] = []
     seen = set()
     for n, u in courses:
         if u not in seen:
             uniq.append((n, u))
             seen.add(u)
     return uniq
 
 
 # ==========================
 # MAIN SCAN LOGIC
 # ==========================
 
 def scan_all(session: requests.Session, courses: list[tuple[str, str]], reference_dt: datetime) -> list[FoundFile]:
     found: list[FoundFile] = []
     seen_files: set[tuple[str, str]] = set()
 
     for course_name_raw, course_url in courses:
 
EOF
)
