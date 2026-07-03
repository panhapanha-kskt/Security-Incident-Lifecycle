#!/usr/bin/env python3
import json, socket, sys, time, os

SOCKET_PATH = "/run/asil/push.sock"
SPOOL_DIR   = "/run/asil/spool"


def _push(alert_json: str) -> bool:
    for attempt in range(3):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect(SOCKET_PATH)
            s.sendall(alert_json.encode("utf-8") + b"\n")
            s.close()
            return True
        except Exception:
            if attempt < 2:
                time.sleep(0.3)
    return False


def main() -> int:
    if len(sys.argv) < 2:
        return 1
    try:
        with open(sys.argv[1], "r") as f:
            alert_json = f.read().strip()
        if not alert_json:
            return 0
        json.loads(alert_json)
    except Exception:
        return 1

    if not _push(alert_json):
        try:
            os.makedirs(SPOOL_DIR, exist_ok=True)
            with open(f"{SPOOL_DIR}/{time.time_ns()}.json", "w") as f:
                f.write(alert_json)
        except Exception:
            return 1  # even the spool write failed — genuinely out of options

    return 0


if __name__ == "__main__":
    sys.exit(main())
