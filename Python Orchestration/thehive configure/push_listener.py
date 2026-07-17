from __future__ import annotations
import json, logging, os, queue, socket, threading

logger = logging.getLogger(__name__)
SOCKET_PATH = os.environ.get("ASIL_PUSH_SOCKET", "/run/asil/push.sock")

class PushListener:
    def __init__(self, socket_path: str = SOCKET_PATH, maxsize: int = 10000) -> None:
        self.socket_path = socket_path
        self.queue: "queue.Queue[str]" = queue.Queue(maxsize=maxsize)
        self._server: socket.socket | None = None
        self._stop = threading.Event()
        self.dropped_count = 0

    def start(self) -> None:
        d = os.path.dirname(self.socket_path)
        os.makedirs(d, exist_ok=True)
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)

        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.socket_path)
        os.chmod(self.socket_path, 0o660)

        try:
            import grp
            gid = grp.getgrnam("wazuh").gr_gid
            os.chown(self.socket_path, -1, gid)
            os.chown(d, -1, gid)
            os.chmod(d, 0o770)
        except Exception:
            logger.warning(
                "Could not chown socket to 'wazuh' group — falling back to 0o660"
            )

        self._server.listen(64)
        self._server.settimeout(1.0)

        threading.Thread(target=self._accept_loop, daemon=True).start()
        logger.info(f"PushListener started  socket={self.socket_path}")

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()

    def _handle_conn(self, conn: socket.socket) -> None:
        buf = b""
        try:
            conn.settimeout(5.0)
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if line:
                        try:
                            self.queue.put_nowait(
                                line.decode("utf-8", errors="replace")
                            )
                        except queue.Full:
                            self.dropped_count += 1
                            logger.warning(
                                "PushListener queue full — dropping alert"
                            )

        except Exception as exc:
            logger.debug(f"PushListener conn error: {exc}")
        finally:
            conn.close()

    def read_new_lines(self):
        try:
            yield ("alerts", self.queue.get(timeout=0.5))
            while True:
                try:
                    yield ("alerts", self.queue.get_nowait())
                except queue.Empty:
                    break
        except queue.Empty:
            return

    def stop(self) -> None:
        self._stop.set()
        if self._server:
            self._server.close()
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)
