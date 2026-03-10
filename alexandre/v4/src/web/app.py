#!/usr/bin/env python3
"""
app.py — HTTP server entry point for SAE302 PKI Web Interface.

Usage:
    python src/web/app.py

Environment variables:
    WEB_PORT    — HTTP port (default: 8080)
    SERVER_IP   — PKI TCP server host (default: 127.0.0.1)
    SERVER_PORT — PKI TCP server port (default: 7890)
    XOR_KEY     — XOR cipher key (default: 42)
"""

import logging
import os
import sys
import threading

# Allow 'from web.xxx import ...' when run as __main__ from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from http.server import HTTPServer
from socketserver import ThreadingMixIn

from dotenv import load_dotenv

_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".env")
load_dotenv(_ENV_PATH, override=False)

from web.api import APIHandler, _session_store
from web.session import WebSessionStore

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


class WebApp(ThreadingMixIn, HTTPServer):
    """
    Threaded HTTP server for the PKI web interface.

    Each request is handled in a separate thread (ThreadingMixIn).
    Shares a single WebSessionStore across all handler instances.
    """

    daemon_threads = True  # daemon threads die when main thread exits

    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port

        # Attach session store to the handler class so all instances share it
        APIHandler.session_store = _session_store

        super().__init__((host, port), APIHandler)
        self._thread: threading.Thread | None = None

    def start(self, block: bool = True) -> None:
        """
        Start the web server.

        Args:
            block: if True (default), block the calling thread.
                   if False, run in a background daemon thread.
        """
        log.info("Web interface listening on http://%s:%s", self.host, self.port)
        if block:
            try:
                self.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                self.stop()
        else:
            self._thread = threading.Thread(
                target=self.serve_forever, daemon=True, name="web-server"
            )
            self._thread.start()

    def stop(self) -> None:
        """Gracefully stop the web server."""
        log.info("Stopping web server…")
        self.shutdown()
        self.server_close()


def main() -> None:
    try:
        port = int(os.getenv("WEB_PORT", "8080"))
    except ValueError:
        port = 8080

    host = os.getenv("WEB_HOST", "0.0.0.0")
    app = WebApp(host=host, port=port)
    app.start(block=True)


if __name__ == "__main__":
    main()
