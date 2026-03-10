"""
session.py — Web session management for SAE302 PKI Web Interface.

Provides WebSession and WebSessionStore for managing authenticated
HTTP sessions with UUID tokens and TTL-based cleanup.
"""

import threading
import time
import uuid


class WebSession:
    """Represents a single authenticated web session."""

    def __init__(self, token: str, username: str, role: str):
        self.token = token
        self.username = username
        self.role = role
        self.last_activity = time.time()
        self.lock = threading.Lock()
        # Connexion TCP persistante vers le serveur PKI (evite la ré-auth TOTP a chaque requete)
        self._proxy = None

    def touch(self):
        """Update last activity timestamp."""
        with self.lock:
            self.last_activity = time.time()

    def is_expired(self, ttl: float) -> bool:
        """Return True if session has exceeded TTL seconds of inactivity."""
        with self.lock:
            return (time.time() - self.last_activity) > ttl

    def __repr__(self) -> str:
        return f"WebSession(user={self.username!r}, role={self.role!r})"


class WebSessionStore:
    """
    Thread-safe in-memory store for WebSession objects.

    Sessions expire after TTL seconds of inactivity.
    A background daemon thread handles periodic cleanup.
    """

    TTL = 3600  # seconds

    def __init__(self, ttl: int = TTL, cleanup_interval: int = 300):
        self._sessions: dict[str, WebSession] = {}
        self._lock = threading.Lock()
        self.ttl = ttl
        self._cleanup_interval = cleanup_interval
        self._start_cleanup_thread()

    def _start_cleanup_thread(self):
        t = threading.Thread(target=self._cleanup_loop, daemon=True)
        t.start()

    def _cleanup_loop(self):
        while True:
            time.sleep(self._cleanup_interval)
            self._purge_expired()

    def _purge_expired(self):
        with self._lock:
            expired = [tok for tok, sess in self._sessions.items()
                       if sess.is_expired(self.ttl)]
            for tok in expired:
                del self._sessions[tok]

    def create(self, username: str, role: str) -> str:
        """Create a new session and return the token."""
        token = str(uuid.uuid4())
        session = WebSession(token, username, role)
        with self._lock:
            self._sessions[token] = session
        return token

    def get(self, token: str) -> "WebSession | None":
        """Return session for token, updating activity, or None if not found/expired."""
        with self._lock:
            session = self._sessions.get(token)
        if session is None:
            return None
        if session.is_expired(self.ttl):
            self.delete(token)
            return None
        session.touch()
        return session

    def delete(self, token: str) -> None:
        """Remove a session by token."""
        with self._lock:
            self._sessions.pop(token, None)

    def count(self) -> int:
        """Return number of active sessions."""
        with self._lock:
            return len(self._sessions)
