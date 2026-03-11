"""
Tests unitaires pour core/network.py.

Aucun socket réel ni PostgreSQL requis — tout est mocké.
"""
import os
import sys
import socket
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.network import (
    ClientSession, PKIServer,
    send_framed, recv_framed, _recv_exact,
)
from utils.crypto import XorCipher


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cipher(key=42):
    return XorCipher(key)


def _make_socket_from_bytes(data: bytes):
    """Mock socket dont recv() consomme séquentiellement les données."""
    buf = bytearray(data)

    def recv(n):
        chunk = bytes(buf[:n])
        del buf[:n]
        return chunk

    mock_sock = MagicMock(spec=socket.socket)
    mock_sock.recv.side_effect = recv
    return mock_sock


# ---------------------------------------------------------------------------
# ClientSession
# ---------------------------------------------------------------------------

class TestClientSession:
    def test_creation(self):
        conn = MagicMock()
        cipher = _make_cipher()
        sess = ClientSession(conn, ("127.0.0.1", 54321), cipher)
        assert sess.ip == "127.0.0.1"
        assert sess.authenticated is False
        assert sess.role is None
        assert sess.username is None
        assert sess.totp_pending is False
        assert sess._pending_user is None
        assert len(sess.challenge) > 0

    def test_repr_anonymous(self):
        sess = ClientSession(MagicMock(), ("10.0.0.1", 1234), _make_cipher())
        assert "anonyme" in repr(sess)
        assert "10.0.0.1" in repr(sess)

    def test_repr_authenticated(self):
        sess = ClientSession(MagicMock(), ("10.0.0.1", 1234), _make_cipher())
        sess.username = "alice"
        assert "alice" in repr(sess)

    def test_unique_challenge_per_session(self):
        c = _make_cipher()
        s1 = ClientSession(MagicMock(), ("127.0.0.1", 1), c)
        s2 = ClientSession(MagicMock(), ("127.0.0.1", 2), c)
        assert s1.challenge != s2.challenge

    def test_addr_stored(self):
        sess = ClientSession(MagicMock(), ("::1", 7890), _make_cipher())
        assert sess.addr == ("::1", 7890)


# ---------------------------------------------------------------------------
# _recv_exact
# ---------------------------------------------------------------------------

class TestRecvExact:
    def test_reads_exact_bytes(self):
        data = b"HelloWorld"
        sock = _make_socket_from_bytes(data)
        result = _recv_exact(sock, 10)
        assert result == b"HelloWorld"

    def test_reads_partial_chunks(self):
        """Simule des petits recv() successifs."""
        full = b"ABCDEFGHIJ"
        # Retourne 2 octets à la fois
        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.recv.side_effect = [full[i:i+2] for i in range(0, 10, 2)]
        result = _recv_exact(mock_sock, 10)
        assert result == full

    def test_returns_none_on_disconnect(self):
        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.recv.return_value = b""
        result = _recv_exact(mock_sock, 10)
        assert result is None

    def test_reads_single_byte(self):
        sock = _make_socket_from_bytes(b"X")
        assert _recv_exact(sock, 1) == b"X"


# ---------------------------------------------------------------------------
# send_framed
# ---------------------------------------------------------------------------

class TestSendFramed:
    def test_sends_header_plus_payload(self):
        mock_sock = MagicMock(spec=socket.socket)
        cipher = _make_cipher(key=0)  # XOR 0 = pas de chiffrement
        message = "hello"
        send_framed(mock_sock, cipher, message)
        sent = mock_sock.sendall.call_args[0][0]
        # Header = 10 octets ASCII (taille du payload)
        header_str = sent[:10].decode("ascii").strip()
        payload_size = int(header_str)
        assert payload_size == len(message.encode("utf-8"))

    def test_payload_is_xor_encrypted(self):
        mock_sock = MagicMock(spec=socket.socket)
        cipher = _make_cipher(key=42)
        message = "test"
        send_framed(mock_sock, cipher, message)
        sent = mock_sock.sendall.call_args[0][0]
        payload = sent[10:]
        # Déchiffrer avec le même cipher
        decrypted = cipher.process(payload).decode("utf-8")
        assert decrypted == message

    def test_empty_message(self):
        mock_sock = MagicMock(spec=socket.socket)
        cipher = _make_cipher(key=1)
        send_framed(mock_sock, cipher, "")
        sent = mock_sock.sendall.call_args[0][0]
        payload_size = int(sent[:10].decode("ascii").strip())
        assert payload_size == 0

    def test_header_is_10_bytes(self):
        mock_sock = MagicMock(spec=socket.socket)
        send_framed(mock_sock, _make_cipher(), "hello PKI")
        sent = mock_sock.sendall.call_args[0][0]
        assert len(sent[:10]) == 10


# ---------------------------------------------------------------------------
# recv_framed
# ---------------------------------------------------------------------------

class TestRecvFramed:
    def _encode_message(self, message: str, cipher: XorCipher) -> bytes:
        """Encode un message comme send_framed le ferait."""
        payload = cipher.process(message.encode("utf-8"))
        header = f"{len(payload):<10}".encode("ascii")
        return header + payload

    def test_roundtrip(self):
        cipher = _make_cipher(key=42)
        data = self._encode_message("hello server", cipher)
        sock = _make_socket_from_bytes(data)
        result = recv_framed(sock, cipher)
        assert result == "hello server"

    def test_returns_none_on_disconnect(self):
        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.recv.return_value = b""
        result = recv_framed(mock_sock, _make_cipher())
        assert result is None

    def test_invalid_header_returns_none(self):
        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.recv.return_value = b"XXXXXXXXXX"  # pas un entier
        result = recv_framed(mock_sock, _make_cipher())
        assert result is None

    def test_zero_size_returns_none(self):
        cipher = _make_cipher()
        header = b"0         "  # 10 octets, taille = 0
        sock = _make_socket_from_bytes(header)
        result = recv_framed(sock, cipher)
        assert result is None

    def test_oversized_payload_returns_none(self):
        cipher = _make_cipher()
        # Taille > 1_000_000
        header = f"{2_000_000:<10}".encode("ascii")
        sock = _make_socket_from_bytes(header)
        result = recv_framed(sock, cipher)
        assert result is None

    def test_payload_disconnect_midway(self):
        cipher = _make_cipher(key=0)
        message = "hello"
        payload = message.encode("utf-8")
        header = f"{len(payload):<10}".encode("ascii")
        # On envoie le header mais payload incomplet (connexion coupée)
        mock_sock = MagicMock(spec=socket.socket)
        buf = bytearray(header)
        calls = [bytes(buf[:10])] + [b""]  # header OK puis disconnect

        def recv(n):
            return calls.pop(0) if calls else b""

        mock_sock.recv.side_effect = recv
        result = recv_framed(mock_sock, cipher)
        assert result is None

    def test_key_zero_no_encryption(self):
        cipher = _make_cipher(key=0)
        data = self._encode_message("plaintext", cipher)
        sock = _make_socket_from_bytes(data)
        assert recv_framed(sock, cipher) == "plaintext"

    def test_unicode_message(self):
        cipher = _make_cipher(key=55)
        msg = "Bonjour ñ café"
        data = self._encode_message(msg, cipher)
        sock = _make_socket_from_bytes(data)
        assert recv_framed(sock, cipher) == msg


# ---------------------------------------------------------------------------
# PKIServer
# ---------------------------------------------------------------------------

class TestPKIServer:
    def _make_server(self, ipv6=False, tls_context=None):
        db = MagicMock()
        handler = MagicMock(return_value="OK response")
        return PKIServer("127.0.0.1", 7890, 42, db, handler,
                         ipv6=ipv6, tls_context=tls_context)

    def test_init_attributes(self):
        srv = self._make_server()
        assert srv.host == "127.0.0.1"
        assert srv.port == 7890
        assert srv.xor_key == 42
        assert srv.ipv6 is False
        assert srv.tls_context is None
        assert srv._running is False

    def test_init_ipv6(self):
        srv = self._make_server(ipv6=True)
        assert srv.ipv6 is True

    def test_stop_sets_running_false(self):
        srv = self._make_server()
        srv._running = True
        mock_sock = MagicMock()
        srv._server_socket = mock_sock
        srv.stop()
        assert srv._running is False
        mock_sock.close.assert_called_once()
        assert srv._server_socket is None

    def test_stop_when_not_started(self):
        srv = self._make_server()
        srv.stop()  # ne doit pas lever d'exception
        assert srv._running is False

    def test_handle_client_normal_flow(self):
        """Teste le cycle complet : banner → commande → réponse → bye."""
        srv = self._make_server()
        srv._running = True

        cipher = XorCipher(42)

        def encode(msg):
            p = cipher.process(msg.encode())
            return f"{len(p):<10}".encode() + p

        # Séquence de réception : une commande puis "bye"
        recv_data = encode("whoami") + encode("bye")
        buf = bytearray(recv_data)

        conn = MagicMock(spec=socket.socket)

        def recv_side(n):
            chunk = bytes(buf[:n])
            del buf[:n]
            return chunk

        conn.recv.side_effect = recv_side

        srv._handle_client(conn, ("127.0.0.1", 12345))

        # Le command_handler doit avoir été appelé deux fois
        assert srv.command_handler.call_count == 2
        conn.close.assert_called_once()

    def test_handle_client_disconnect_immediately(self):
        """Le client se déconnecte dès l'envoi du banner."""
        srv = self._make_server()
        srv._running = True
        conn = MagicMock(spec=socket.socket)
        # recv retourne b"" (déconnexion) après envoi du banner
        conn.recv.return_value = b""
        srv._handle_client(conn, ("127.0.0.1", 9999))
        conn.close.assert_called_once()
        # Aucune commande traitée
        srv.command_handler.assert_not_called()

    def test_handle_client_tls_failure(self):
        """Un échec TLS doit fermer la connexion proprement."""
        import ssl
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = ssl.SSLError("handshake failed")
        srv = self._make_server(tls_context=mock_ctx)
        srv._running = True
        conn = MagicMock(spec=socket.socket)
        srv._handle_client(conn, ("127.0.0.1", 9999))
        conn.close.assert_called_once()

    def test_handle_client_tls_wraps_socket(self):
        """Avec TLS, wrap_socket doit être appelé."""
        mock_ctx = MagicMock()
        wrapped_conn = MagicMock(spec=socket.socket)
        mock_ctx.wrap_socket.return_value = wrapped_conn
        # Déconnexion immédiate après banner
        wrapped_conn.recv.return_value = b""

        srv = self._make_server(tls_context=mock_ctx)
        srv._running = True
        conn = MagicMock(spec=socket.socket)
        srv._handle_client(conn, ("127.0.0.1", 9999))

        mock_ctx.wrap_socket.assert_called_once_with(conn, server_side=True)
        wrapped_conn.close.assert_called_once()

    def test_handle_client_connection_error(self):
        """Une ConnectionError pendant la boucle doit être gérée proprement."""
        srv = self._make_server()
        srv._running = True
        conn = MagicMock(spec=socket.socket)

        cipher = XorCipher(42)

        def encode(msg):
            p = cipher.process(msg.encode())
            return f"{len(p):<10}".encode() + p

        recv_data = bytearray(encode("hello"))

        def recv_side(n):
            if recv_data:
                chunk = bytes(recv_data[:n])
                del recv_data[:n]
                return chunk
            raise ConnectionResetError("peer reset")

        conn.recv.side_effect = recv_side
        srv.command_handler.side_effect = ConnectionResetError("peer reset")

        srv._handle_client(conn, ("127.0.0.1", 9999))
        conn.close.assert_called_once()
