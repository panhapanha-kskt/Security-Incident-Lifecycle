#THEHIVE_KEY = "OsI8EYIrkrecKmH7tq0pUAt24l9Sp9P9"
#!/usr/bin/env python3
THEHIVE_URL = "https://192.168.200.1:8443"
# THEHIVE_KEY is read exclusively from the environment variable THEHIVE_KEY.
# Never hardcode it here.
import os
THEHIVE_KEY = os.environ.get("THEHIVE_KEY", "")
THEHIVE_VERIFY_SSL = False
THEHIVE_TIMEOUT = 15
THEHIVE_RETRIES = 2
CASE_MIN_SEVERITY = "MEDIUM"
CASE_DEDUP_SEC = 600