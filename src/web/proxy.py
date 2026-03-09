"""
proxy.py — PKI TCP proxy for SAE302 PKI Web Interface.

Connects to the TCP PKI server using the exact same XOR stream cipher
and 10-byte framing protocol as src/client.py.
"""

import hashlib
import os
import socket
import sys

# Allow imports from src/ when running standalone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.crypto import XorCipher


class PKIProxy:
    """
    Connects to the TCP PKI server and proxies commands from the web layer.

    Protocol (identical to PKIClient in src/client.py):
      - XOR stream cipher with shared key
      - 10-byte ASCII framing header: zero-padded payload length, left-justified
      - Challenge-response auth: SHA256(challenge + SHA256(password))
      - TOTP/OTP_REQUIRED flow supported (caller must supply otp_code)

    Environment variables:
      SERVER_IP   — PKI server hostname/IP (default: 127.0.0.1)
      SERVER_PORT — PKI server port (default: 7890)
      XOR_KEY     — XOR cipher key 0-255 (default: 42)
    """

    HEADER_SIZE = 10

    def __init__(self):
        _server_ip = os.getenv("SERVER_IP", "127.0.0.1")
        try:
            _server_port = int(os.getenv("SERVER_PORT", "7890"))
        except ValueError:
            _server_port = 7890
        try:
            _xor_key = int(os.getenv("XOR_KEY", "42"))
        except ValueError:
            _xor_key = 42

        self.host = _server_ip
        self.port = _server_port
        self.cipher = XorCipher(_xor_key)
        self.sock: socket.socket | None = None
        self.username: str | None = None
        self.role: str | None = None
        self._challenge: str | None = None

    # ------------------------------------------------------------------
    # Low-level framing (mirrors PKIClient._send_framed / _recv_framed)
    # ------------------------------------------------------------------

    def _send_framed(self, message: str) -> None:
        payload = self.cipher.process(message.encode("utf-8"))
        header = f"{len(payload):<10}".encode("ascii")
        self.sock.sendall(header + payload)

    def _recv_exact(self, size: int) -> bytes | None:
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _recv_framed(self) -> str | None:
        header = self._recv_exact(self.HEADER_SIZE)
        if header is None:
            return None
        try:
            payload_size = int(header.decode("ascii").strip())
        except (ValueError, UnicodeDecodeError):
            return None
        if payload_size <= 0 or payload_size > 1_000_000:
            return None
        payload = self._recv_exact(payload_size)
        if payload is None:
            return None
        return self.cipher.process(payload).decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(self, username: str, password: str, otp_code: str = "") -> bool:
        """
        Open a TCP connection to the PKI server and authenticate.

        Handles:
          1. TCP connect + hello/challenge reception
          2. Challenge-response SHA256 login
          3. OTP_REQUIRED flow if TOTP is enabled for the user
             (caller may pass otp_code; if empty and OTP required, returns False)

        Returns:
            True on successful authentication, False otherwise.
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((self.host, self.port))
        except (ConnectionRefusedError, OSError, socket.timeout):
            self.sock = None
            return False

        # Receive hello + challenge
        hello = self._recv_framed()
        if hello is None:
            self.sock = None
            return False

        self._challenge = None
        if "CHALL:" in hello:
            self._challenge = hello.split("CHALL:")[1].strip()

        # Build and send login command
        if self._challenge:
            pwd_sha256 = hashlib.sha256(password.encode("utf-8")).hexdigest()
            response_hash = hashlib.sha256(
                (self._challenge + pwd_sha256).encode("utf-8")
            ).hexdigest()
            response = self.send_command(f"login {username} CHALL:{response_hash}")
        else:
            response = self.send_command(f"login {username} {password}")

        if response is None:
            return False

        # Handle TOTP challenge
        if response == "OTP_REQUIRED":
            if not otp_code:
                # Cannot complete MFA without an OTP code
                return False
            response = self.send_command(f"otp {otp_code}")
            if response is None:
                return False

        if response.startswith("OK"):
            parts = response.split()
            self.username = username
            self.role = parts[1] if len(parts) > 1 else "user"
            return True

        return False

    def send_command(self, cmd: str) -> str | None:
        """
        Send a text command to the PKI server and return the response.

        Returns None if the connection is lost.
        """
        if not self.sock:
            return None
        try:
            self._send_framed(cmd)
            return self._recv_framed()
        except (socket.timeout, OSError):
            self.sock = None
            return None

    def disconnect(self) -> None:
        """Send bye and close the TCP connection."""
        if self.sock:
            try:
                self.send_command("bye")
            except OSError:
                pass
            finally:
                try:
                    self.sock.close()
                except OSError:
                    pass
                self.sock = None
