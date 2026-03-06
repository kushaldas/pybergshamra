"""Comprehensive tests for pybergshamra — Python bindings for Bergshamra XML Security."""

import hashlib
import os
from pathlib import Path

import pytest

import pybergshamra
from pybergshamra import (
    Algorithm,
    BergshamraError,
    C14nMode,
    CertificateError,
    CryptoError,
    DsigContext,
    EncContext,
    EncryptionError,
    Key,
    KeyLoadError,
    KeysManager,
    KeyUsage,
    VerifiedKeyInfo,
    VerifiedReference,
    VerifyResult,
    XmlError,
)

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

TEST_DATA = Path(__file__).resolve().parent.parent / "test-data"
KEYS_DIR = TEST_DATA / "keys"
RSA_DIR = KEYS_DIR / "rsa"
EC_DIR = KEYS_DIR / "ec"
DSIG_DIR = TEST_DATA / "aleksey-xmldsig-01"
ENC_DIR = TEST_DATA / "aleksey-xmlenc-01"
SIGNED_DIR = TEST_DATA / "signedxml"


@pytest.fixture
def rsa_private_key():
    """Load RSA 2048 private key from PEM."""
    pem = (RSA_DIR / "rsa-2048-key.pem").read_bytes()
    return pybergshamra.load_rsa_private_pem(pem)


@pytest.fixture
def rsa_public_key():
    """Load RSA 2048 public key from PEM."""
    pem = (RSA_DIR / "rsa-2048-pubkey.pem").read_bytes()
    return pybergshamra.load_rsa_public_pem(pem)


@pytest.fixture
def rsa_cert_key():
    """Load RSA 2048 certificate from PEM."""
    pem = (RSA_DIR / "rsa-2048-cert.pem").read_bytes()
    return pybergshamra.load_x509_cert_pem(pem)


@pytest.fixture
def ec_p256_private_key():
    """Load EC P-256 private key from PEM."""
    pem = (EC_DIR / "ec-prime256v1-key.pem").read_bytes()
    return pybergshamra.load_ec_p256_private_pem(pem)


@pytest.fixture
def ec_p384_private_key():
    """Load EC P-384 private key from PEM."""
    pem = (EC_DIR / "ec-prime384v1-key.pem").read_bytes()
    return pybergshamra.load_ec_p384_private_pem(pem)


@pytest.fixture
def ec_p521_private_key():
    """Load EC P-521 private key from PEM."""
    pem = (EC_DIR / "ec-prime521v1-key.pem").read_bytes()
    return pybergshamra.load_ec_p521_private_pem(pem)


@pytest.fixture
def hmac_key():
    """Load HMAC key from raw binary."""
    data = (KEYS_DIR / "hmackey.bin").read_bytes()
    return pybergshamra.load_hmac_key(data)


@pytest.fixture
def aes128_keys():
    """Load named AES-128 keys from keys.xml."""
    keys = pybergshamra.load_keys_file(str(KEYS_DIR / "keys.xml"))
    return [k for k in keys if k.name and "aes128" in k.name]


@pytest.fixture
def ca_cert_pem():
    """Read the CA cert PEM bytes."""
    return (KEYS_DIR / "cacert.pem").read_bytes()


@pytest.fixture
def ca_cert_der():
    """Read the CA cert DER bytes."""
    return (KEYS_DIR / "cacert.der").read_bytes()


# ===========================================================================
# 1. Algorithm URI constants
# ===========================================================================


class TestAlgorithmConstants:
    """Test that Algorithm class attributes return correct W3C URIs."""

    def test_sha256_uri(self):
        assert Algorithm.SHA256 == "http://www.w3.org/2001/04/xmlenc#sha256"

    def test_rsa_sha256_uri(self):
        assert (
            Algorithm.RSA_SHA256 == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        )

    def test_hmac_sha256_uri(self):
        assert (
            Algorithm.HMAC_SHA256
            == "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
        )

    def test_aes128_cbc_uri(self):
        assert Algorithm.AES128_CBC == "http://www.w3.org/2001/04/xmlenc#aes128-cbc"

    def test_c14n_uri(self):
        assert Algorithm.C14N == "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"

    def test_exc_c14n_uri(self):
        assert Algorithm.EXC_C14N == "http://www.w3.org/2001/10/xml-exc-c14n#"

    def test_rsa_pkcs1_uri(self):
        assert Algorithm.RSA_PKCS1 == "http://www.w3.org/2001/04/xmlenc#rsa-1_5"

    def test_eddsa_ed25519_uri(self):
        assert (
            Algorithm.EDDSA_ED25519
            == "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"
        )

    def test_enveloped_signature_uri(self):
        assert (
            Algorithm.ENVELOPED_SIGNATURE
            == "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
        )

    def test_pbkdf2_uri(self):
        assert Algorithm.PBKDF2 == "http://www.w3.org/2009/xmlenc11#pbkdf2"


# ===========================================================================
# 2. Key loading
# ===========================================================================


class TestKeyLoading:
    """Test key loading functions."""

    def test_load_rsa_private_pem(self, rsa_private_key):
        assert rsa_private_key.algorithm_name == "RSA"
        assert rsa_private_key.has_private_key is True

    def test_load_rsa_public_pem(self, rsa_public_key):
        assert rsa_public_key.algorithm_name == "RSA"
        assert rsa_public_key.has_private_key is False

    def test_load_x509_cert_pem(self, rsa_cert_key):
        assert rsa_cert_key.algorithm_name == "RSA"
        # An X509 cert contains a public key, no private
        assert rsa_cert_key.has_private_key is False
        # Should have at least one cert in the chain
        chain = rsa_cert_key.x509_chain
        assert len(chain) >= 1
        assert isinstance(chain[0], bytes)

    def test_load_x509_cert_der(self):
        der = (RSA_DIR / "rsa-2048-cert.der").read_bytes()
        key = pybergshamra.load_x509_cert_der(der)
        assert key.algorithm_name == "RSA"
        assert len(key.x509_chain) >= 1

    def test_load_ec_p256_private(self, ec_p256_private_key):
        assert ec_p256_private_key.algorithm_name == "EC-P256"
        assert ec_p256_private_key.has_private_key is True

    def test_load_ec_p384_private(self, ec_p384_private_key):
        assert ec_p384_private_key.algorithm_name == "EC-P384"
        assert ec_p384_private_key.has_private_key is True

    def test_load_ec_p521_private(self, ec_p521_private_key):
        assert ec_p521_private_key.algorithm_name == "EC-P521"
        assert ec_p521_private_key.has_private_key is True

    def test_load_hmac_key(self, hmac_key):
        assert hmac_key.algorithm_name == "HMAC"
        assert hmac_key.has_private_key is True  # symmetric = always True

    def test_load_aes_key(self):
        # 16 bytes = AES-128
        key = pybergshamra.load_aes_key(b"\x00" * 16)
        assert key.algorithm_name == "AES"
        assert key.has_private_key is True  # symmetric

    def test_load_des3_key(self):
        # 24 bytes = 3DES
        key = pybergshamra.load_des3_key(b"\x00" * 24)
        assert key.algorithm_name == "3DES"
        assert key.has_private_key is True  # symmetric

    def test_load_key_file(self):
        key = pybergshamra.load_key_file(str(RSA_DIR / "rsa-2048-key.pem"))
        assert key.algorithm_name == "RSA"
        assert key.has_private_key is True

    def test_load_key_file_with_password(self):
        key = pybergshamra.load_key_file_with_password(
            str(KEYS_DIR / "cakey.pem"), "secret123"
        )
        assert key.algorithm_name == "RSA"
        assert key.has_private_key is True

    def test_load_pkcs12(self):
        data = (RSA_DIR / "rsa-2048-key.p12").read_bytes()
        key = pybergshamra.load_pkcs12(data, "secret123")
        assert key.algorithm_name == "RSA"
        assert key.has_private_key is True

    def test_load_pem_auto_rsa(self):
        pem = (RSA_DIR / "rsa-2048-key.pem").read_bytes()
        key = pybergshamra.load_pem_auto(pem)
        assert key.algorithm_name == "RSA"

    def test_load_pem_auto_with_password(self):
        pem = (KEYS_DIR / "cakey.pem").read_bytes()
        key = pybergshamra.load_pem_auto(pem, password="secret123")
        assert key.algorithm_name == "RSA"

    def test_load_spki_pem(self):
        pem = (RSA_DIR / "rsa-2048-pubkey.pem").read_bytes()
        key = pybergshamra.load_spki_pem(pem)
        assert key.algorithm_name == "RSA"
        assert key.has_private_key is False

    def test_load_spki_der(self):
        der = (RSA_DIR / "rsa-2048-pubkey.der").read_bytes()
        key = pybergshamra.load_spki_der(der)
        assert key.algorithm_name == "RSA"
        assert key.has_private_key is False

    def test_load_key_file_invalid_path(self):
        with pytest.raises(Exception):
            pybergshamra.load_key_file("/nonexistent/path.pem")


# ===========================================================================
# 3. Key properties and methods
# ===========================================================================


class TestKeyProperties:
    """Test Key name, usage, and method accessors."""

    def test_name_get_set(self, rsa_private_key):
        assert rsa_private_key.name is None
        rsa_private_key.name = "my-rsa-key"
        assert rsa_private_key.name == "my-rsa-key"
        rsa_private_key.name = None
        assert rsa_private_key.name is None

    def test_usage_get_set(self, rsa_private_key):
        rsa_private_key.usage = KeyUsage.Sign
        assert rsa_private_key.usage == KeyUsage.Sign
        rsa_private_key.usage = KeyUsage.Any
        assert rsa_private_key.usage == KeyUsage.Any

    def test_key_usage_enum_values(self):
        assert KeyUsage.Sign == KeyUsage.Sign
        assert KeyUsage.Verify != KeyUsage.Sign

    def test_to_spki_der_rsa_public(self, rsa_public_key):
        spki = rsa_public_key.to_spki_der()
        assert spki is not None
        assert isinstance(spki, bytes)
        assert len(spki) > 0

    def test_to_spki_der_hmac_none(self, hmac_key):
        spki = hmac_key.to_spki_der()
        assert spki is None

    def test_symmetric_key_bytes_hmac(self, hmac_key):
        raw = hmac_key.symmetric_key_bytes()
        assert raw is not None
        assert isinstance(raw, bytes)
        assert len(raw) > 0

    def test_symmetric_key_bytes_aes(self):
        data = b"\xab" * 16
        key = pybergshamra.load_aes_key(data)
        raw = key.symmetric_key_bytes()
        assert raw == data

    def test_symmetric_key_bytes_rsa_none(self, rsa_private_key):
        raw = rsa_private_key.symmetric_key_bytes()
        assert raw is None

    def test_ec_public_key_bytes_p256(self, ec_p256_private_key):
        pub_bytes = ec_p256_private_key.ec_public_key_bytes()
        assert pub_bytes is not None
        # P-256 uncompressed point: 1 + 32 + 32 = 65 bytes
        assert len(pub_bytes) == 65
        assert pub_bytes[0] == 0x04  # uncompressed marker

    def test_ec_public_key_bytes_rsa_none(self, rsa_private_key):
        assert rsa_private_key.ec_public_key_bytes() is None

    def test_to_key_value_xml_rsa(self, rsa_public_key):
        xml_str = rsa_public_key.to_key_value_xml()
        assert xml_str is not None
        assert "<ds:RSAKeyValue>" in xml_str
        assert "<ds:Modulus>" in xml_str

    def test_to_key_value_xml_custom_prefix(self, rsa_public_key):
        xml_str = rsa_public_key.to_key_value_xml(prefix="dsig")
        assert xml_str is not None
        assert "<dsig:RSAKeyValue>" in xml_str

    def test_to_key_value_xml_hmac_none(self, hmac_key):
        assert hmac_key.to_key_value_xml() is None

    def test_repr(self, rsa_private_key):
        r = repr(rsa_private_key)
        assert "Key(" in r
        assert "RSA" in r

    def test_has_private_key_symmetric(self):
        """All symmetric keys (HMAC, AES, DES3) should report has_private_key=True."""
        hmac = pybergshamra.load_hmac_key(b"secret")
        assert hmac.has_private_key is True
        aes = pybergshamra.load_aes_key(b"\x00" * 16)
        assert aes.has_private_key is True
        des3 = pybergshamra.load_des3_key(b"\x00" * 24)
        assert des3.has_private_key is True


# ===========================================================================
# 4. X25519 key loading and methods
# ===========================================================================


class TestX25519Keys:
    """Test X25519 key loading and accessor methods."""

    def test_load_x25519_private_raw(self):
        raw = b"\x01" * 32
        key = pybergshamra.load_x25519_private_raw(raw)
        assert key.algorithm_name == "X25519"
        priv_bytes = key.x25519_private_key_bytes()
        assert priv_bytes is not None
        assert len(priv_bytes) == 32

    def test_load_x25519_public_raw(self):
        # A 32-byte public key
        raw = b"\x02" * 32
        key = pybergshamra.load_x25519_public_raw(raw)
        assert key.algorithm_name == "X25519"
        pub_bytes = key.x25519_public_key_bytes()
        assert pub_bytes is not None
        assert len(pub_bytes) == 32

    def test_x25519_rsa_returns_none(self, rsa_private_key):
        assert rsa_private_key.x25519_public_key_bytes() is None
        assert rsa_private_key.x25519_private_key_bytes() is None


# ===========================================================================
# 5. KeysManager
# ===========================================================================


class TestKeysManager:
    """Test KeysManager operations."""

    def test_empty_manager(self):
        mgr = KeysManager()
        assert len(mgr) == 0
        assert not mgr  # __bool__ → False when empty
        assert mgr.first_key() is None

    def test_add_key_and_len(self, rsa_private_key):
        mgr = KeysManager()
        mgr.add_key(rsa_private_key)
        assert len(mgr) == 1
        assert mgr  # __bool__ → True when non-empty

    def test_first_key(self, rsa_private_key, hmac_key):
        mgr = KeysManager()
        mgr.add_key(rsa_private_key)
        mgr.add_key(hmac_key)
        first = mgr.first_key()
        assert first is not None
        assert first.algorithm_name == "RSA"

    def test_insert_key_first(self, rsa_private_key, hmac_key):
        mgr = KeysManager()
        mgr.add_key(rsa_private_key)
        mgr.insert_key_first(hmac_key)
        first = mgr.first_key()
        assert first is not None
        assert first.algorithm_name == "HMAC"

    def test_keys_list(self, rsa_private_key, hmac_key):
        mgr = KeysManager()
        mgr.add_key(rsa_private_key)
        mgr.add_key(hmac_key)
        all_keys = mgr.keys()
        assert len(all_keys) == 2
        algorithms = {k.algorithm_name for k in all_keys}
        assert "RSA" in algorithms
        assert "HMAC" in algorithms

    def test_find_by_name(self, rsa_private_key):
        mgr = KeysManager()
        rsa_private_key.name = "test-rsa"
        mgr.add_key(rsa_private_key)
        found = mgr.find_by_name("test-rsa")
        assert found is not None
        assert found.algorithm_name == "RSA"
        assert mgr.find_by_name("nonexistent") is None

    def test_find_by_usage(self, rsa_private_key):
        mgr = KeysManager()
        rsa_private_key.usage = KeyUsage.Sign
        mgr.add_key(rsa_private_key)
        found = mgr.find_by_usage(KeyUsage.Sign)
        assert found is not None
        assert mgr.find_by_usage(KeyUsage.Encrypt) is None

    def test_find_rsa(self, rsa_private_key):
        mgr = KeysManager()
        mgr.add_key(rsa_private_key)
        assert mgr.find_rsa() is not None
        assert mgr.find_hmac() is None

    def test_find_rsa_private(self, rsa_private_key, rsa_public_key):
        mgr = KeysManager()
        mgr.add_key(rsa_public_key)
        mgr.add_key(rsa_private_key)
        found = mgr.find_rsa_private()
        assert found is not None
        assert found.has_private_key is True

    def test_find_hmac(self, hmac_key):
        mgr = KeysManager()
        mgr.add_key(hmac_key)
        assert mgr.find_hmac() is not None

    def test_find_aes_and_aes_by_size(self):
        aes128 = pybergshamra.load_aes_key(b"\x00" * 16)
        aes128.name = "aes-128"
        aes256 = pybergshamra.load_aes_key(b"\x00" * 32)
        aes256.name = "aes-256"
        mgr = KeysManager()
        mgr.add_key(aes128)
        mgr.add_key(aes256)
        assert mgr.find_aes() is not None
        found128 = mgr.find_aes_by_size(16)
        assert found128 is not None
        found256 = mgr.find_aes_by_size(32)
        assert found256 is not None
        assert mgr.find_aes_by_size(24) is None  # no 192-bit key

    def test_find_des3(self):
        des3 = pybergshamra.load_des3_key(b"\x00" * 24)
        mgr = KeysManager()
        mgr.add_key(des3)
        assert mgr.find_des3() is not None

    def test_find_ec_curves(
        self, ec_p256_private_key, ec_p384_private_key, ec_p521_private_key
    ):
        mgr = KeysManager()
        mgr.add_key(ec_p256_private_key)
        mgr.add_key(ec_p384_private_key)
        mgr.add_key(ec_p521_private_key)
        assert mgr.find_ec_p256() is not None
        assert mgr.find_ec_p384() is not None
        assert mgr.find_ec_p521() is not None

    def test_find_x25519(self):
        key = pybergshamra.load_x25519_private_raw(b"\x01" * 32)
        mgr = KeysManager()
        mgr.add_key(key)
        assert mgr.find_x25519() is not None

    def test_find_returns_none_empty(self):
        mgr = KeysManager()
        assert mgr.find_rsa() is None
        assert mgr.find_hmac() is None
        assert mgr.find_aes() is None
        assert mgr.find_des3() is None
        assert mgr.find_ec_p256() is None
        assert mgr.find_ed25519() is None
        assert mgr.find_x25519() is None
        assert mgr.find_pq() is None
        assert mgr.find_dh() is None

    def test_cert_management(self, ca_cert_der):
        mgr = KeysManager()
        assert mgr.has_trusted_certs() is False
        assert mgr.trusted_certs() == []
        assert mgr.untrusted_certs() == []
        assert mgr.crls() == []

        mgr.add_trusted_cert(ca_cert_der)
        assert mgr.has_trusted_certs() is True
        certs = mgr.trusted_certs()
        assert len(certs) == 1
        assert certs[0] == ca_cert_der

        mgr.add_untrusted_cert(ca_cert_der)
        assert len(mgr.untrusted_certs()) == 1

        mgr.add_crl(b"\x00\x01\x02")
        assert len(mgr.crls()) == 1

    def test_repr(self):
        mgr = KeysManager()
        r = repr(mgr)
        assert "KeysManager" in r
        assert "keys=0" in r


# ===========================================================================
# 6. XML key file loading (keys.xml)
# ===========================================================================


class TestXmlKeysLoading:
    """Test loading keys from xmlsec keys.xml format."""

    def test_load_keys_file(self):
        keys = pybergshamra.load_keys_file(str(KEYS_DIR / "keys.xml"))
        assert len(keys) > 0
        names = {k.name for k in keys if k.name}
        assert "test-hmac-sha1" in names
        assert "test-aes128" in names
        assert "test-rsa" in names

    def test_parse_keys_xml(self):
        xml = (KEYS_DIR / "keys.xml").read_text()
        keys = pybergshamra.parse_keys_xml(xml)
        assert len(keys) > 0
        names = {k.name for k in keys if k.name}
        assert "test-hmac-sha1" in names

    def test_parse_keys_xml_matches_load_keys_file(self):
        file_keys = pybergshamra.load_keys_file(str(KEYS_DIR / "keys.xml"))
        xml_str = (KEYS_DIR / "keys.xml").read_text()
        parsed_keys = pybergshamra.parse_keys_xml(xml_str)
        assert len(file_keys) == len(parsed_keys)
        file_names = sorted(k.name for k in file_keys if k.name)
        parsed_names = sorted(k.name for k in parsed_keys if k.name)
        assert file_names == parsed_names


# ===========================================================================
# 7. C14N canonicalization
# ===========================================================================


class TestCanonicalization:
    """Test XML canonicalization."""

    def test_c14n_mode_properties(self):
        mode = C14nMode.Inclusive
        assert "c14n" in mode.uri.lower() or "C14N" in mode.uri
        assert mode.with_comments is False
        assert mode.is_exclusive is False

    def test_c14n_mode_with_comments(self):
        mode = C14nMode.InclusiveWithComments
        assert mode.with_comments is True

    def test_c14n_mode_exclusive(self):
        mode = C14nMode.Exclusive
        assert mode.is_exclusive is True
        assert mode.with_comments is False

    def test_c14n_mode_exclusive_with_comments(self):
        mode = C14nMode.ExclusiveWithComments
        assert mode.is_exclusive is True
        assert mode.with_comments is True

    def test_c14n_mode_from_uri(self):
        uri = Algorithm.C14N
        mode = C14nMode.from_uri(uri)
        assert mode is not None
        assert mode == C14nMode.Inclusive

    def test_c14n_mode_from_uri_unknown(self):
        assert C14nMode.from_uri("http://example.com/unknown") is None

    def test_c14n_mode_repr(self):
        r = repr(C14nMode.Inclusive)
        assert "Inclusive" in r

    def test_canonicalize_simple(self):
        xml = "<root><child>hello</child></root>"
        result = pybergshamra.canonicalize(xml, C14nMode.Inclusive)
        assert isinstance(result, bytes)
        assert b"<root>" in result
        assert b"<child>hello</child>" in result

    def test_canonicalize_removes_xml_decl(self):
        xml = '<?xml version="1.0"?><root/>'
        result = pybergshamra.canonicalize(xml, C14nMode.Inclusive)
        assert b"<?xml" not in result
        assert b"<root>" in result

    def test_canonicalize_attribute_ordering(self):
        # C14N sorts attributes lexicographically
        xml = '<root z="1" a="2"/>'
        result = pybergshamra.canonicalize(xml, C14nMode.Inclusive)
        decoded = result.decode("utf-8")
        a_pos = decoded.index('a="2"')
        z_pos = decoded.index('z="1"')
        assert a_pos < z_pos

    def test_canonicalize_exclusive(self):
        xml = '<root xmlns:ns="http://example.com"><child>text</child></root>'
        result = pybergshamra.canonicalize(xml, C14nMode.Exclusive)
        assert isinstance(result, bytes)

    def test_canonicalize_with_comments(self):
        xml = "<root><!-- comment --><child/></root>"
        with_comments = pybergshamra.canonicalize(xml, C14nMode.InclusiveWithComments)
        without_comments = pybergshamra.canonicalize(xml, C14nMode.Inclusive)
        assert b"<!-- comment -->" in with_comments
        assert b"<!-- comment -->" not in without_comments

    def test_canonicalize_subtree(self):
        xml = '<root><child Id="sub1">content</child><other>skip</other></root>'
        result = pybergshamra.canonicalize_subtree(xml, "sub1", C14nMode.Inclusive)
        decoded = result.decode("utf-8")
        assert "content" in decoded
        # The subtree should only be the <child> element
        assert "<other>" not in decoded

    def test_canonicalize_subtree_not_found(self):
        xml = '<root><child Id="sub1">content</child></root>'
        with pytest.raises(ValueError, match="not found"):
            pybergshamra.canonicalize_subtree(xml, "nonexistent", C14nMode.Inclusive)


# ===========================================================================
# 8. DSig — Signature verification
# ===========================================================================


class TestVerification:
    """Test XML Digital Signature verification."""

    def test_verify_valid_saml(self):
        """Verify a self-contained signed SAML response."""
        xml = (SIGNED_DIR / "valid-saml.xml").read_text()
        mgr = KeysManager()
        ctx = DsigContext(mgr)
        ctx.insecure = True  # skip cert validation (self-signed)
        ctx.skip_time_checks = True
        result = pybergshamra.verify(ctx, xml)
        assert result.is_valid is True
        assert bool(result) is True
        assert result.reason is None
        assert result.references is not None
        assert len(result.references) >= 1
        assert result.key_info is not None
        assert result.signature_node_id is not None
        assert isinstance(result.signature_node_id, int)

    def test_verify_result_references(self):
        """Check VerifiedReference properties."""
        xml = (SIGNED_DIR / "valid-saml.xml").read_text()
        mgr = KeysManager()
        ctx = DsigContext(mgr)
        ctx.insecure = True
        ctx.skip_time_checks = True
        result = pybergshamra.verify(ctx, xml)
        assert result.is_valid
        refs = result.references
        assert refs is not None
        for ref in refs:
            assert isinstance(ref, VerifiedReference)
            assert isinstance(ref.uri, str)
            # resolved_node_id may be None for external refs
            r = repr(ref)
            assert "VerifiedReference" in r

    def test_verify_result_key_info(self):
        """Check VerifiedKeyInfo properties."""
        xml = (SIGNED_DIR / "valid-saml.xml").read_text()
        mgr = KeysManager()
        ctx = DsigContext(mgr)
        ctx.insecure = True
        ctx.skip_time_checks = True
        result = pybergshamra.verify(ctx, xml)
        assert result.is_valid
        ki = result.key_info
        assert ki is not None
        assert isinstance(ki, VerifiedKeyInfo)
        assert isinstance(ki.algorithm, str)
        assert len(ki.algorithm) > 0
        # key_name may or may not be present
        # x509_chain should have the inline cert
        assert len(ki.x509_chain) >= 1
        r = repr(ki)
        assert "VerifiedKeyInfo" in r

    def test_verify_invalid_changed_content(self):
        """Verify fails with tampered content."""
        xml = (SIGNED_DIR / "invalid-signature-changed-content.xml").read_text()
        mgr = KeysManager()
        ctx = DsigContext(mgr)
        ctx.insecure = True
        ctx.skip_time_checks = True
        result = pybergshamra.verify(ctx, xml)
        assert result.is_valid is False
        assert bool(result) is False
        assert result.reason is not None
        assert len(result.reason) > 0
        assert result.references is None
        assert result.key_info is None
        assert result.signature_node_id is None

    def test_verify_invalid_signature_value(self):
        """Verify fails with tampered signature value."""
        xml = (SIGNED_DIR / "invalid-signature-signature-value.xml").read_text()
        mgr = KeysManager()
        ctx = DsigContext(mgr)
        ctx.insecure = True
        ctx.skip_time_checks = True
        result = pybergshamra.verify(ctx, xml)
        assert result.is_valid is False

    def test_verify_result_repr(self):
        xml = (SIGNED_DIR / "valid-saml.xml").read_text()
        mgr = KeysManager()
        ctx = DsigContext(mgr)
        ctx.insecure = True
        ctx.skip_time_checks = True
        result = pybergshamra.verify(ctx, xml)
        r = repr(result)
        assert "VerifyResult" in r

    def test_verify_result_bool(self):
        """Test that VerifyResult supports `if result:` idiom."""
        xml = (SIGNED_DIR / "valid-saml.xml").read_text()
        mgr = KeysManager()
        ctx = DsigContext(mgr)
        ctx.insecure = True
        ctx.skip_time_checks = True
        result = pybergshamra.verify(ctx, xml)
        # Should work as a boolean
        if result:
            pass  # valid
        else:
            pytest.fail("VerifyResult should be truthy for valid signature")


# ===========================================================================
# 9. DSig — Signing
# ===========================================================================


class TestSigning:
    """Test XML Digital Signature signing."""

    def test_sign_rsa(self):
        """Sign a template with RSA key."""
        template = (DSIG_DIR / "enveloping-sha256-rsa-sha256.tmpl").read_text()
        pem = (RSA_DIR / "rsa-2048-key.pem").read_bytes()
        key = pybergshamra.load_key_file(str(RSA_DIR / "rsa-2048-key.pem"))
        key.name = "TestKeyName-rsa-2048"

        cert_pem = (RSA_DIR / "rsa-2048-cert.pem").read_bytes()
        cert_key = pybergshamra.load_x509_cert_pem(cert_pem)

        mgr = KeysManager()
        mgr.add_key(key)
        mgr.add_key(cert_key)
        ctx = DsigContext(mgr)
        signed_xml = pybergshamra.sign(ctx, template)
        assert isinstance(signed_xml, str)
        assert "<SignatureValue>" in signed_xml
        assert "<DigestValue>" in signed_xml
        # The SignatureValue should no longer be empty
        # Extract content between tags
        sv_start = signed_xml.index("<SignatureValue>") + len("<SignatureValue>")
        sv_end = signed_xml.index("</SignatureValue>")
        sv_content = signed_xml[sv_start:sv_end].strip()
        assert len(sv_content) > 0

    def test_sign_hmac(self):
        """Sign a template with HMAC key."""
        template = (DSIG_DIR / "enveloping-sha256-hmac-sha256.tmpl").read_text()
        hmac_data = (KEYS_DIR / "hmackey.bin").read_bytes()
        key = pybergshamra.load_hmac_key(hmac_data)
        key.name = "TeskKeyName-Hmac"

        mgr = KeysManager()
        mgr.add_key(key)
        ctx = DsigContext(mgr)
        signed_xml = pybergshamra.sign(ctx, template)
        assert "<SignatureValue>" in signed_xml

    def test_sign_then_verify_rsa(self):
        """Sign and then verify round-trip with RSA."""
        template = (DSIG_DIR / "enveloping-sha256-rsa-sha256.tmpl").read_text()
        key = pybergshamra.load_key_file(str(RSA_DIR / "rsa-2048-key.pem"))
        key.name = "TestKeyName-rsa-2048"

        cert_pem = (RSA_DIR / "rsa-2048-cert.pem").read_bytes()
        cert_key = pybergshamra.load_x509_cert_pem(cert_pem)

        mgr = KeysManager()
        mgr.add_key(key)
        mgr.add_key(cert_key)
        ctx = DsigContext(mgr)

        # Sign
        signed_xml = pybergshamra.sign(ctx, template)

        # Verify
        verify_mgr = KeysManager()
        verify_mgr.add_key(key)
        verify_mgr.add_key(cert_key)
        verify_ctx = DsigContext(verify_mgr)
        verify_ctx.insecure = True
        verify_ctx.skip_time_checks = True
        result = pybergshamra.verify(verify_ctx, signed_xml)
        assert result.is_valid, f"Verification failed: {result.reason}"

    def test_sign_then_verify_hmac(self):
        """Sign and then verify round-trip with HMAC."""
        template = (DSIG_DIR / "enveloping-sha256-hmac-sha256.tmpl").read_text()
        hmac_data = (KEYS_DIR / "hmackey.bin").read_bytes()
        key = pybergshamra.load_hmac_key(hmac_data)
        key.name = "TeskKeyName-Hmac"

        mgr = KeysManager()
        mgr.add_key(key)
        ctx = DsigContext(mgr)

        # Sign
        signed_xml = pybergshamra.sign(ctx, template)

        # Verify — reuse same key
        verify_mgr = KeysManager()
        verify_key = pybergshamra.load_hmac_key(hmac_data)
        verify_key.name = "TeskKeyName-Hmac"
        verify_mgr.add_key(verify_key)
        verify_ctx = DsigContext(verify_mgr)
        result = pybergshamra.verify(verify_ctx, signed_xml)
        assert result.is_valid, f"Verification failed: {result.reason}"


# ===========================================================================
# 10. DsigContext properties
# ===========================================================================


class TestDsigContext:
    """Test DsigContext property getters/setters."""

    def test_default_values(self):
        mgr = KeysManager()
        ctx = DsigContext(mgr)
        assert ctx.debug is False
        assert ctx.insecure is False
        assert ctx.verify_keys is False
        assert ctx.verification_time is None
        assert ctx.skip_time_checks is False
        assert ctx.enabled_key_data_x509 is False
        assert ctx.trusted_keys_only is False
        assert ctx.strict_verification is False
        assert ctx.hmac_min_out_len == 0
        assert ctx.base_dir is None

    def test_set_properties(self):
        mgr = KeysManager()
        ctx = DsigContext(mgr)
        ctx.debug = True
        assert ctx.debug is True
        ctx.insecure = True
        assert ctx.insecure is True
        ctx.verify_keys = True
        assert ctx.verify_keys is True
        ctx.verification_time = "2024-01-01+00:00:00"
        assert ctx.verification_time == "2024-01-01+00:00:00"
        ctx.skip_time_checks = True
        assert ctx.skip_time_checks is True
        ctx.enabled_key_data_x509 = True
        assert ctx.enabled_key_data_x509 is True
        ctx.trusted_keys_only = True
        assert ctx.trusted_keys_only is True
        ctx.strict_verification = True
        assert ctx.strict_verification is True
        ctx.hmac_min_out_len = 128
        assert ctx.hmac_min_out_len == 128
        ctx.base_dir = "/tmp"
        assert ctx.base_dir == "/tmp"

    def test_add_id_attr(self):
        mgr = KeysManager()
        ctx = DsigContext(mgr)
        ctx.add_id_attr("AssertionID")
        # No direct way to verify, but it should not raise

    def test_add_url_map(self):
        mgr = KeysManager()
        ctx = DsigContext(mgr)
        ctx.add_url_map("http://example.com/data", "/tmp/data.xml")


# ===========================================================================
# 11. XML Encryption
# ===========================================================================


class TestEncryption:
    """Test XML Encryption encrypt/decrypt."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypt data with AES-128-CBC template, then decrypt."""
        # Load AES-128 key from keys.xml
        keys = pybergshamra.load_keys_file(str(KEYS_DIR / "keys.xml"))
        aes_key = None
        for k in keys:
            if k.name == "test-aes128":
                aes_key = k
                break
        assert aes_key is not None, "Could not find test-aes128 key"

        template = (ENC_DIR / "enc-aes128cbc-keyname.tmpl").read_text()
        plaintext = b"AES 128 test"

        # Encrypt
        enc_mgr = KeysManager()
        enc_mgr.add_key(aes_key)
        enc_ctx = EncContext(enc_mgr)
        encrypted_xml = pybergshamra.encrypt(enc_ctx, template, plaintext)
        assert isinstance(encrypted_xml, str)
        assert "<CipherValue>" in encrypted_xml

        # Decrypt
        dec_mgr = KeysManager()
        # Create a fresh copy of the key for decrypt
        dec_keys = pybergshamra.load_keys_file(str(KEYS_DIR / "keys.xml"))
        for k in dec_keys:
            if k.name == "test-aes128":
                dec_mgr.add_key(k)
                break
        dec_ctx = EncContext(dec_mgr)
        decrypted = pybergshamra.decrypt_to_bytes(dec_ctx, encrypted_xml)
        assert decrypted == plaintext

    def test_decrypt_existing(self):
        """Decrypt a pre-encrypted file."""
        encrypted_xml = (ENC_DIR / "enc-aes128cbc-keyname.xml").read_text()
        keys = pybergshamra.load_keys_file(str(KEYS_DIR / "keys.xml"))
        mgr = KeysManager()
        for k in keys:
            if k.name == "test-aes128":
                mgr.add_key(k)
                break
        ctx = EncContext(mgr)
        decrypted = pybergshamra.decrypt_to_bytes(ctx, encrypted_xml)
        assert decrypted == b"AES 128 test"

    def test_enc_context_properties(self):
        mgr = KeysManager()
        ctx = EncContext(mgr)
        assert ctx.disable_cipher_reference is False
        ctx.disable_cipher_reference = True
        assert ctx.disable_cipher_reference is True

    def test_enc_context_add_id_attr(self):
        mgr = KeysManager()
        ctx = EncContext(mgr)
        ctx.add_id_attr("CustomId")  # Should not raise


# ===========================================================================
# 12. Crypto primitives — digest
# ===========================================================================


class TestDigest:
    """Test the digest() function."""

    def test_sha256_known_value(self):
        data = b"hello"
        result = pybergshamra.digest(Algorithm.SHA256, data)
        expected = hashlib.sha256(data).digest()
        assert result == expected

    def test_sha1_known_value(self):
        data = b"test data"
        result = pybergshamra.digest(Algorithm.SHA1, data)
        expected = hashlib.sha1(data).digest()
        assert result == expected

    def test_sha384(self):
        data = b"some data"
        result = pybergshamra.digest(Algorithm.SHA384, data)
        expected = hashlib.sha384(data).digest()
        assert result == expected

    def test_sha512(self):
        data = b"more data"
        result = pybergshamra.digest(Algorithm.SHA512, data)
        expected = hashlib.sha512(data).digest()
        assert result == expected

    def test_digest_empty_data(self):
        result = pybergshamra.digest(Algorithm.SHA256, b"")
        expected = hashlib.sha256(b"").digest()
        assert result == expected

    def test_digest_invalid_algorithm(self):
        with pytest.raises(Exception):
            pybergshamra.digest("http://example.com/invalid", b"data")


# ===========================================================================
# 13. Crypto primitives — KDFs
# ===========================================================================


class TestKDFs:
    """Test PBKDF2, HKDF, and ConcatKDF."""

    def test_pbkdf2_derive(self):
        """PBKDF2 with HMAC-SHA256, 32-byte output."""
        password = b"password"
        salt = b"salt"
        result = pybergshamra.pbkdf2_derive(
            password=password,
            salt=salt,
            iteration_count=4096,
            key_length=32,
            prf_uri=Algorithm.HMAC_SHA256,
        )
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_pbkdf2_deterministic(self):
        """Same inputs produce same output."""
        r1 = pybergshamra.pbkdf2_derive(b"pw", b"salt", 1000, 16, Algorithm.HMAC_SHA256)
        r2 = pybergshamra.pbkdf2_derive(b"pw", b"salt", 1000, 16, Algorithm.HMAC_SHA256)
        assert r1 == r2

    def test_hkdf_derive(self):
        """HKDF basic derivation."""
        ikm = b"\x0b" * 22
        result = pybergshamra.hkdf_derive(
            shared_secret=ikm,
            key_length=32,
            prf_uri=Algorithm.HMAC_SHA256,
        )
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_hkdf_with_salt_and_info(self):
        ikm = b"shared_secret_material"
        salt = b"salt_value"
        info = b"context_info"
        result = pybergshamra.hkdf_derive(
            shared_secret=ikm,
            key_length=16,
            prf_uri=Algorithm.HMAC_SHA256,
            salt=salt,
            info=info,
        )
        assert len(result) == 16

    def test_concat_kdf(self):
        """ConcatKDF basic derivation."""
        shared_secret = b"\x01\x02\x03\x04" * 8
        result = pybergshamra.concat_kdf(
            shared_secret=shared_secret,
            key_length=16,
            digest_uri=Algorithm.SHA256,
        )
        assert isinstance(result, bytes)
        assert len(result) == 16

    def test_concat_kdf_deterministic(self):
        ss = b"secret" * 4
        r1 = pybergshamra.concat_kdf(ss, 32, Algorithm.SHA256)
        r2 = pybergshamra.concat_kdf(ss, 32, Algorithm.SHA256)
        assert r1 == r2


# ===========================================================================
# 14. X509 certificate chain validation
# ===========================================================================


class TestCertValidation:
    """Test validate_cert_chain function."""

    def test_self_signed_with_skip_time(self, ca_cert_der):
        """A self-signed CA cert validates against itself with time checks skipped."""
        pybergshamra.validate_cert_chain(
            leaf_der=ca_cert_der,
            trusted_certs=[ca_cert_der],
            skip_time_checks=True,
        )
        # Should not raise

    def test_invalid_chain_raises(self):
        """Random bytes as leaf cert should raise CertificateError."""
        with pytest.raises(Exception):
            pybergshamra.validate_cert_chain(
                leaf_der=b"\x00\x01\x02\x03",
                trusted_certs=[],
            )

    def test_leaf_without_trusted_raises(self, ca_cert_der):
        """Valid cert but no trusted roots should raise."""
        # Load the RSA cert (which is signed by CA)
        rsa_cert_der = (RSA_DIR / "rsa-2048-cert.der").read_bytes()
        with pytest.raises(Exception):
            pybergshamra.validate_cert_chain(
                leaf_der=rsa_cert_der,
                trusted_certs=[],
                skip_time_checks=True,
            )


# ===========================================================================
# 15. X509 KeyInfo builders
# ===========================================================================


class TestKeyInfoBuilders:
    """Test build_x509_key_info and build_x509_key_info_from_der."""

    def test_build_from_der(self, ca_cert_der):
        xml_str = pybergshamra.build_x509_key_info_from_der([ca_cert_der])
        assert "<ds:KeyInfo" in xml_str
        assert "<ds:X509Data>" in xml_str
        assert "<ds:X509Certificate>" in xml_str

    def test_build_from_b64(self):
        import base64

        cert_der = (RSA_DIR / "rsa-2048-cert.der").read_bytes()
        cert_b64 = base64.b64encode(cert_der).decode("ascii")
        xml_str = pybergshamra.build_x509_key_info([cert_b64])
        assert "<ds:KeyInfo" in xml_str
        assert "<ds:X509Certificate>" in xml_str

    def test_build_multiple_certs(self, ca_cert_der):
        rsa_cert_der = (RSA_DIR / "rsa-2048-cert.der").read_bytes()
        xml_str = pybergshamra.build_x509_key_info_from_der([rsa_cert_der, ca_cert_der])
        # Should contain two X509Certificate elements
        count = xml_str.count("<ds:X509Certificate>")
        assert count == 2


# ===========================================================================
# 16. Exception hierarchy
# ===========================================================================


class TestExceptions:
    """Test exception class hierarchy."""

    def test_exception_hierarchy(self):
        assert issubclass(XmlError, BergshamraError)
        assert issubclass(CryptoError, BergshamraError)
        assert issubclass(KeyLoadError, BergshamraError)
        assert issubclass(pybergshamra.AlgorithmError, BergshamraError)
        assert issubclass(EncryptionError, BergshamraError)
        assert issubclass(CertificateError, BergshamraError)

    def test_bergshamra_error_is_exception(self):
        assert issubclass(BergshamraError, Exception)

    def test_can_catch_base(self):
        """Specific exceptions should be catchable as BergshamraError."""
        with pytest.raises(BergshamraError):
            # Invalid XML should raise XmlError (subclass of BergshamraError)
            mgr = KeysManager()
            ctx = DsigContext(mgr)
            pybergshamra.verify(ctx, "not valid xml <")


# ===========================================================================
# 17. Ed25519 key loading
# ===========================================================================


class TestEd25519Keys:
    """Test Ed25519 key loading (no files on disk; use DER constants)."""

    # Ed25519 private key PKCS#8 DER (from RFC 8410 / IETF test vectors)
    # This is a minimal 48-byte PKCS#8 wrapper around a 32-byte private key
    ED25519_PKCS8_DER = bytes.fromhex(
        "302e020100300506032b657004220420"
        "d4ee72dbf913584ad5b6d8f1f769f8ad"
        "3afe7c28cbf1d4fbe097a88f44755842"
    )

    # Corresponding Ed25519 public key SPKI DER
    ED25519_SPKI_DER = bytes.fromhex(
        "302a300506032b6570032100"
        "19bf44096984cdfe8541bac167dc3b96"
        "c85086aa30b6b6cb0c5c38ad703166e1"
    )

    def test_load_ed25519_private(self):
        key = pybergshamra.load_ed25519_private_pkcs8_der(self.ED25519_PKCS8_DER)
        assert key.algorithm_name == "Ed25519"
        assert key.has_private_key is True

    def test_load_ed25519_public(self):
        key = pybergshamra.load_ed25519_public_spki_der(self.ED25519_SPKI_DER)
        assert key.algorithm_name == "Ed25519"
        assert key.has_private_key is False

    def test_find_ed25519_in_manager(self):
        key = pybergshamra.load_ed25519_private_pkcs8_der(self.ED25519_PKCS8_DER)
        mgr = KeysManager()
        mgr.add_key(key)
        found = mgr.find_ed25519()
        assert found is not None
        assert found.algorithm_name == "Ed25519"


# ===========================================================================
# 18. Comprehensive C14nMode enum
# ===========================================================================


class TestC14nModeComprehensive:
    """Test all 6 C14N modes."""

    @pytest.mark.parametrize(
        "mode,expected_exclusive,expected_comments",
        [
            (C14nMode.Inclusive, False, False),
            (C14nMode.InclusiveWithComments, False, True),
            (C14nMode.Inclusive11, False, False),
            (C14nMode.Inclusive11WithComments, False, True),
            (C14nMode.Exclusive, True, False),
            (C14nMode.ExclusiveWithComments, True, True),
        ],
    )
    def test_mode_properties(self, mode, expected_exclusive, expected_comments):
        assert mode.is_exclusive == expected_exclusive
        assert mode.with_comments == expected_comments
        assert isinstance(mode.uri, str)
        assert len(mode.uri) > 0

    def test_from_uri_roundtrip(self):
        for mode in [
            C14nMode.Inclusive,
            C14nMode.InclusiveWithComments,
            C14nMode.Exclusive,
            C14nMode.ExclusiveWithComments,
        ]:
            uri = mode.uri
            recovered = C14nMode.from_uri(uri)
            assert recovered is not None
            assert recovered == mode


# ===========================================================================
# 19. Smoke tests — basic import and instantiation
# ===========================================================================


class TestSmoke:
    """Basic smoke tests for module import and class creation."""

    def test_import(self):
        import pybergshamra

        assert hasattr(pybergshamra, "verify")
        assert hasattr(pybergshamra, "sign")
        assert hasattr(pybergshamra, "encrypt")
        assert hasattr(pybergshamra, "decrypt")
        assert hasattr(pybergshamra, "canonicalize")
        assert hasattr(pybergshamra, "digest")

    def test_keys_manager_creation(self):
        mgr = KeysManager()
        assert len(mgr) == 0

    def test_dsig_context_creation(self):
        mgr = KeysManager()
        ctx = DsigContext(mgr)
        assert ctx.debug is False

    def test_enc_context_creation(self):
        mgr = KeysManager()
        ctx = EncContext(mgr)
        assert ctx.disable_cipher_reference is False
