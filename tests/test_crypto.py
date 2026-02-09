#!/usr/bin/env python3
"""
Tests unitaires pour le module utils/crypto.py.

Lancement :
    python -m pytest tests/test_crypto.py -v
"""

import os
import sys
import tempfile
import pytest

# Ajout du dossier src/ au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from utils.crypto import (
    XorCipher,
    generate_key_pair,
    generate_csr,
    show_key_info,
    show_csr_info,
)


# ===================================================================
#  TESTS XorCipher
# ===================================================================

class TestXorCipher:
    """Tests pour la classe XorCipher."""

    def test_chiffrement_dechiffrement(self):
        """XOR applique deux fois doit redonner le message original."""
        cipher = XorCipher(42)
        message = b"Hello PKI!"
        encrypted = cipher.process(message)
        decrypted = cipher.process(encrypted)
        assert decrypted == message

    def test_chiffrement_modifie_donnees(self):
        """Le chiffrement doit produire des donnees differentes (sauf cle=0)."""
        cipher = XorCipher(42)
        message = b"Test"
        encrypted = cipher.process(message)
        assert encrypted != message

    def test_cle_zero(self):
        """Avec cle=0, XOR ne modifie pas les donnees."""
        cipher = XorCipher(0)
        message = b"Pas de chiffrement"
        assert cipher.process(message) == message

    def test_donnees_vides(self):
        """XOR sur donnees vides doit retourner des donnees vides."""
        cipher = XorCipher(42)
        assert cipher.process(b"") == b""

    def test_cle_invalide_negative(self):
        """Une cle negative doit lever ValueError."""
        with pytest.raises(ValueError):
            XorCipher(-1)

    def test_cle_invalide_trop_grande(self):
        """Une cle > 255 doit lever ValueError."""
        with pytest.raises(ValueError):
            XorCipher(256)

    def test_cle_invalide_type(self):
        """Une cle non-entiere doit lever ValueError."""
        with pytest.raises(ValueError):
            XorCipher("42")

    def test_cle_limite_255(self):
        """La cle 255 doit fonctionner (borne haute)."""
        cipher = XorCipher(255)
        message = b"Limite"
        assert cipher.process(cipher.process(message)) == message


# ===================================================================
#  TESTS generate_key_pair
# ===================================================================

class TestGenerateKeyPair:
    """Tests pour la generation de cles RSA."""

    def test_generation_basique(self, tmp_path):
        """Genere une paire de cles et verifie que les fichiers existent."""
        priv, pub = generate_key_pair(str(tmp_path), key_size=2048)
        assert os.path.isfile(priv)
        assert os.path.isfile(pub)

    def test_contenu_pem(self, tmp_path):
        """Les fichiers generes doivent contenir des en-tetes PEM valides."""
        priv, pub = generate_key_pair(str(tmp_path), key_size=2048)
        with open(priv, "rb") as f:
            assert b"BEGIN RSA PRIVATE KEY" in f.read()
        with open(pub, "rb") as f:
            assert b"BEGIN PUBLIC KEY" in f.read()

    def test_permissions_cle_privee(self, tmp_path):
        """La cle privee doit avoir les permissions 600."""
        priv, _ = generate_key_pair(str(tmp_path), key_size=2048)
        mode = oct(os.stat(priv).st_mode & 0o777)
        assert mode == "0o600"

    def test_taille_insuffisante(self, tmp_path):
        """Une taille < 2048 doit lever ValueError."""
        with pytest.raises(ValueError):
            generate_key_pair(str(tmp_path), key_size=1024)

    def test_creation_repertoire(self, tmp_path):
        """Le repertoire doit etre cree automatiquement s'il n'existe pas."""
        new_dir = os.path.join(str(tmp_path), "sous", "dossier")
        priv, pub = generate_key_pair(new_dir, key_size=2048)
        assert os.path.isfile(priv)
        assert os.path.isfile(pub)


# ===================================================================
#  TESTS generate_csr
# ===================================================================

class TestGenerateCSR:
    """Tests pour la generation de CSR."""

    @pytest.fixture
    def key_pair(self, tmp_path):
        """Fixture : genere une paire de cles pour les tests CSR."""
        return generate_key_pair(str(tmp_path), key_size=2048)

    def test_generation_basique(self, tmp_path, key_pair):
        """Genere une CSR et verifie que le fichier existe."""
        priv, _ = key_pair
        csr_path = os.path.join(str(tmp_path), "test.csr")
        result = generate_csr(priv, cn="TestUser", output_path=csr_path)
        assert os.path.isfile(result)

    def test_contenu_pem(self, tmp_path, key_pair):
        """Le fichier CSR doit contenir un en-tete PEM valide."""
        priv, _ = key_pair
        csr_path = os.path.join(str(tmp_path), "test.csr")
        generate_csr(priv, cn="TestUser", output_path=csr_path)
        with open(csr_path, "rb") as f:
            assert b"BEGIN CERTIFICATE REQUEST" in f.read()

    def test_cn_vide(self, key_pair):
        """Un CN vide doit lever ValueError."""
        priv, _ = key_pair
        with pytest.raises(ValueError):
            generate_csr(priv, cn="")

    def test_country_invalide(self, key_pair):
        """Un code pays invalide doit lever ValueError."""
        priv, _ = key_pair
        with pytest.raises(ValueError):
            generate_csr(priv, cn="Test", country="FRA")

    def test_cle_introuvable(self):
        """Un chemin de cle inexistant doit lever FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            generate_csr("/chemin/inexistant.pem", cn="Test")

    def test_cle_invalide(self, tmp_path):
        """Un fichier qui n'est pas une cle PEM doit lever ValueError."""
        fake_key = os.path.join(str(tmp_path), "fake.pem")
        with open(fake_key, "w") as f:
            f.write("ceci n'est pas une cle")
        with pytest.raises(ValueError):
            generate_csr(fake_key, cn="Test")


# ===================================================================
#  TESTS show_key_info / show_csr_info
# ===================================================================

class TestShowInfo:
    """Tests pour les fonctions d'inspection."""

    def test_show_private_key(self, tmp_path):
        """show_key_info doit identifier une cle privee."""
        priv, _ = generate_key_pair(str(tmp_path), key_size=2048)
        info = show_key_info(priv)
        assert "privee" in info.lower()
        assert "2048" in info

    def test_show_public_key(self, tmp_path):
        """show_key_info doit identifier une cle publique."""
        _, pub = generate_key_pair(str(tmp_path), key_size=2048)
        info = show_key_info(pub)
        assert "publique" in info.lower()
        assert "2048" in info

    def test_show_csr(self, tmp_path):
        """show_csr_info doit afficher le sujet de la CSR."""
        priv, _ = generate_key_pair(str(tmp_path), key_size=2048)
        csr_path = os.path.join(str(tmp_path), "test.csr")
        generate_csr(priv, cn="Alice", org="TestOrg", output_path=csr_path)
        info = show_csr_info(csr_path)
        assert "Alice" in info
        assert "sha256" in info.lower()

    def test_show_key_fichier_inexistant(self):
        """show_key_info avec fichier inexistant doit lever FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            show_key_info("/chemin/inexistant.pem")

    def test_show_csr_fichier_inexistant(self):
        """show_csr_info avec fichier inexistant doit lever FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            show_csr_info("/chemin/inexistant.csr")
