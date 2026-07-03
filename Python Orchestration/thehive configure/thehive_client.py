#!/usr/bin/env python3
import urllib3
import requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class TheHiveClient:
    def __init__(
        self,
        url: str,
        api_key: str,
        verify_ssl: bool = False,
        timeout: int = 15,
        retries: int = 2,
    ):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.retries = retries
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })
        self.session.verify = verify_ssl

    def ping(self) -> bool:
        try:
            r = self.session.get(
                f"{self.url}/api/v1/status",
                timeout=self.timeout,
            )
            return r.status_code == 200
        except Exception:
            return False
    def create_case(self, case_data: dict):
        r = self.session.post(
            f"{self.url}/api/v1/case",
            json=case_data,
            timeout=self.timeout,
        )
        if r.status_code in (200, 201):
            return r.json()
        raise RuntimeError(
            f"Failed creating case ({r.status_code}) : {r.text}"
        )
