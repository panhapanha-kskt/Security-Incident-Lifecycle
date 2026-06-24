THEHIVE_KEY = "your-thehive-key"
#!/usr/bin/env python3
#THEHIVE_URL = "https://192.168.200.1:8443"
THEHIVE_URL = "https://172.24.80.95:8443"
import os
THEHIVE_KEY = os.environ.get("THEHIVE_KEY", "")
THEHIVE_VERIFY_SSL = False
THEHIVE_TIMEOUT = 15
THEHIVE_RETRIES = 2
CASE_MIN_SEVERITY = "MEDIUM"
CASE_DEDUP_SEC = 600
