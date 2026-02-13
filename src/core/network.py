"""
core/network.py — Serveur TCP multi-thread avec chiffrement XOR.

Gere les connexions entrantes, le framing des messages (header 10 octets),
et dispatche les commandes vers le module commands.
"""

import os
import sys
import socket
import secrets
import logging
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.crypto import XorCipher

log = logging.getLogger(__name__)

HEADER_SIZE = 10  # Taille du header de framing (10 caracteres ASCII)


class ClientSession:
    """Etat d'une connexion client."""

    def __init__(self, conn: socket.socket, addr: tuple, cipher: XorCipher):
        self.conn = conn
        self.addr = addr
        self.cipher = cipher
        self.user_id: int | None = None
        self.username: str | None = None
        self.role: str | None = None
        self.ip: str = addr[0]
        self.authenticated = False
        self.challenge: str = secrets.token_hex(16)

    def __repr__(self) -> str:
        user = self.username or "anonyme"
        return f"Session({self.ip}, user={user})"


def send_framed(conn: socket.socket, cipher: XorCipher, message: str) -> None:
    """
    Envoie un message avec framing : header 10 octets (taille) + payload XOR.

    Le header est la taille du payload chiffre, encodee en ASCII sur 10 chars.
    """
    payload = cipher.process(message.encode("utf-8"))
    header = f"{len(payload):<10}".encode("ascii")
    conn.sendall(header + payload)


def recv_framed(conn: socket.socket, cipher: XorCipher) -> str | None:
    """
    Recoit un message avec framing : header 10 octets + payload XOR.

    Returns:
        Message dechiffre ou None si la connexion est fermee.
    """
    # Lire le header
    header = _recv_exact(conn, HEADER_SIZE)
    if header is None:
        return None

    try:
        payload_size = int(header.decode("ascii").strip())
    except (ValueError, UnicodeDecodeError):
        log.warning("Header invalide recu")
        return None

    if payload_size <= 0 or payload_size > 1_000_000:
        log.warning("Taille de payload invalide : %d", payload_size)
        return None

    # Lire le payload
    payload = _recv_exact(conn, payload_size)
    if payload is None:
        return None

    return cipher.process(payload).decode("utf-8", errors="replace")


def _recv_exact(conn: socket.socket, size: int) -> bytes | None:
    """Recoit exactement `size` octets depuis la socket."""
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


class PKIServer:
    """Serveur TCP multi-thread pour la gestion de PKI."""

    def __init__(self, host: str, port: int, xor_key: int,
                 db, command_handler):
        """
        Args:
            host            : adresse d'ecoute.
            port            : port d'ecoute.
            xor_key         : cle XOR partagee avec les clients.
            db              : instance Database.
            command_handler : fonction(session, command) -> reponse.
        """
        self.host = host
        self.port = port
        self.xor_key = xor_key
        self.cipher = XorCipher(xor_key)
        self.db = db
        self.command_handler = command_handler
        self._server_socket: socket.socket | None = None
        self._running = False

    def start(self) -> None:
        """Demarre le serveur et accepte les connexions."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(5)
        self._running = True

        log.info("Serveur PKI demarre sur %s:%s", self.host, self.port)

        try:
            while self._running:
                try:
                    conn, addr = self._server_socket.accept()
                    log.info("Connexion entrante : %s:%s", addr[0], addr[1])
                    t = threading.Thread(
                        target=self._handle_client,
                        args=(conn, addr),
                        daemon=True,
                    )
                    t.start()
                except OSError:
                    if self._running:
                        raise
                    break
        except KeyboardInterrupt:
            log.info("Arret du serveur (Ctrl+C)")
        finally:
            self.stop()

    def stop(self) -> None:
        """Arrete le serveur proprement."""
        self._running = False
        if self._server_socket:
            self._server_socket.close()
            self._server_socket = None
            log.info("Serveur arrete")

    def _handle_client(self, conn: socket.socket, addr: tuple) -> None:
        """Gere une connexion client dans un thread dedie."""
        cipher = XorCipher(self.xor_key)
        session = ClientSession(conn, addr, cipher)

        try:
            # Envoi du message hello avec challenge
            send_framed(conn, cipher, f"SAE302 PKI Server ready CHALL:{session.challenge}")

            while self._running:
                message = recv_framed(conn, cipher)
                if message is None:
                    log.info("Client deconnecte : %s", session)
                    break

                message = message.strip()
                if not message:
                    continue

                log.debug("RECV [%s]: %s", session, message)

                # Traitement de la commande
                response = self.command_handler(session, message, self.db)

                # Envoi de la reponse
                send_framed(conn, cipher, response)

                # Si bye, fermer la connexion
                if message.lower() == "bye":
                    break

        except ConnectionError:
            log.info("Connexion perdue : %s", session)
        except Exception as e:
            log.error("Erreur client %s : %s", session, e)
        finally:
            conn.close()
