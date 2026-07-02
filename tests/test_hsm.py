"""PKCS#11 / HSM integration tests for pybergshamra, driven by SoftHSM2.

These tests are skipped unless a SoftHSM2 token has been provisioned by
``hsm-test/setup.sh`` and ``SOFTHSM2_CONF`` points at the generated config.
The CI ``hsm`` job runs that setup before invoking pytest; locally:

    bash hsm-test/setup.sh
    SOFTHSM2_CONF=hsm-test/softhsm2.local.conf pytest tests/test_hsm.py -v
"""

import os
from pathlib import Path

import pytest

import pybergshamra
from pybergshamra import Algorithm

TEST_DATA = Path(__file__).resolve().parent.parent / "test-data"
DSIG_DIR = TEST_DATA / "aleksey-xmldsig-01"
ENC_DIR = TEST_DATA / "aleksey-xmlenc-01"

# Candidate SoftHSM2 module locations (kept in sync with hsm-test/setup.sh).
_SOFTHSM_LIB_CANDIDATES = [
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib64/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
]

PIN = "1234"


def _softhsm_lib():
    for cand in _SOFTHSM_LIB_CANDIDATES:
        if os.path.exists(cand):
            return cand
    return None


_LIB = _softhsm_lib()
_TOKEN_READY = _LIB is not None and os.environ.get("SOFTHSM2_CONF") is not None

pytestmark = pytest.mark.skipif(
    not _TOKEN_READY,
    reason="SoftHSM2 not provisioned; run hsm-test/setup.sh and set SOFTHSM2_CONF",
)


@pytest.fixture(scope="module")
def session():
    provider = pybergshamra.Pkcs11Provider(_LIB)
    return provider.open_session(PIN)


# ---------------------------------------------------------------------------
# Provider / session
# ---------------------------------------------------------------------------


class TestProvider:
    def test_open_session(self):
        provider = pybergshamra.Pkcs11Provider(_LIB)
        sess = provider.open_session(PIN)
        assert sess is not None

    def test_wrong_pin_fails(self):
        provider = pybergshamra.Pkcs11Provider(_LIB)
        with pytest.raises(Exception):
            provider.open_session("0000")

    def test_missing_module_fails(self):
        with pytest.raises(Exception):
            pybergshamra.Pkcs11Provider("/nonexistent/libsofthsm2.so")


# ---------------------------------------------------------------------------
# Direct sign / verify round-trips
# ---------------------------------------------------------------------------


class TestSignVerify:
    def test_rsa_sign_verify(self, session):
        signer = pybergshamra.Pkcs11Signer(session, "test-rsa-key", Algorithm.RSA_SHA256)
        verifier = pybergshamra.Pkcs11Verifier(session, "test-rsa-key", Algorithm.RSA_SHA256)
        sig = signer.sign(b"hello world")
        assert isinstance(sig, bytes) and len(sig) == 256
        assert verifier.verify(b"hello world", sig) is True
        assert verifier.verify(b"tampered", sig) is False

    def test_rsa_pss_sign_verify(self, session):
        signer = pybergshamra.Pkcs11Signer(session, "test-rsa-key", Algorithm.RSA_PSS_SHA256)
        verifier = pybergshamra.Pkcs11Verifier(session, "test-rsa-key", Algorithm.RSA_PSS_SHA256)
        sig = signer.sign(b"data")
        assert verifier.verify(b"data", sig) is True

    def test_ec_p256_sign_verify(self, session):
        signer = pybergshamra.Pkcs11Signer(
            session, "test-ec-key", Algorithm.ECDSA_SHA256, ec_curve="P-256"
        )
        verifier = pybergshamra.Pkcs11Verifier(
            session, "test-ec-key", Algorithm.ECDSA_SHA256, ec_curve="P-256"
        )
        sig = signer.sign(b"hello")
        assert verifier.verify(b"hello", sig) is True
        assert verifier.verify(b"goodbye", sig) is False

    def test_ecdsa_requires_curve(self, session):
        with pytest.raises(Exception):
            pybergshamra.Pkcs11Signer(session, "test-ec-key", Algorithm.ECDSA_SHA256)

    def test_hmac_sign_verify(self, session):
        signer = pybergshamra.Pkcs11Signer(session, "test-hmac-key", Algorithm.HMAC_SHA256)
        verifier = pybergshamra.Pkcs11Verifier(session, "test-hmac-key", Algorithm.HMAC_SHA256)
        sig = signer.sign(b"message")
        assert verifier.verify(b"message", sig) is True
        assert verifier.verify(b"other", sig) is False

    def test_unsupported_algorithm(self, session):
        with pytest.raises(Exception):
            pybergshamra.Pkcs11Signer(session, "test-rsa-key", "urn:bogus")

    def test_unknown_key_label(self, session):
        with pytest.raises(Exception):
            pybergshamra.Pkcs11Signer(session, "no-such-key", Algorithm.RSA_SHA256)


# ---------------------------------------------------------------------------
# RSA-OAEP encrypt / decrypt (SoftHSM2 supports SHA-1 MGF only)
# ---------------------------------------------------------------------------


class TestKeyTransport:
    def test_rsa_oaep_roundtrip(self, session):
        enc = pybergshamra.Pkcs11Encryptor(
            session, "test-rsa-enc", Algorithm.RSA_OAEP,
            digest=Algorithm.SHA1, mgf=Algorithm.MGF1_SHA1,
        )
        dec = pybergshamra.Pkcs11Decryptor(
            session, "test-rsa-enc", Algorithm.RSA_OAEP,
            digest=Algorithm.SHA1, mgf=Algorithm.MGF1_SHA1,
        )
        ciphertext = enc.encrypt(b"top secret session key")
        assert dec.decrypt(ciphertext) == b"top secret session key"


# ---------------------------------------------------------------------------
# Full XML-DSig signing/verification with key material on the token
# ---------------------------------------------------------------------------


class TestXmlDsig:
    def _template(self):
        return (DSIG_DIR / "enveloping-sha256-rsa-sha256.tmpl").read_text()

    def test_hsm_sign_then_hsm_verify(self, session):
        km = pybergshamra.KeysManager()

        sign_ctx = pybergshamra.DsigContext(km)
        sign_ctx.set_hsm_signer(
            pybergshamra.Pkcs11Signer(session, "test-rsa-key", Algorithm.RSA_SHA256)
        )
        signed_xml = pybergshamra.sign(sign_ctx, self._template())
        assert "SignatureValue" in signed_xml

        verify_ctx = pybergshamra.DsigContext(km, secure_defaults=False)
        verify_ctx.set_hsm_verifier(
            pybergshamra.Pkcs11Verifier(session, "test-rsa-key", Algorithm.RSA_SHA256)
        )
        result = pybergshamra.verify(verify_ctx, signed_xml)
        assert bool(result) is True

    def test_hsm_verify_rejects_tampered(self, session):
        km = pybergshamra.KeysManager()
        sign_ctx = pybergshamra.DsigContext(km)
        sign_ctx.set_hsm_signer(
            pybergshamra.Pkcs11Signer(session, "test-rsa-key", Algorithm.RSA_SHA256)
        )
        signed_xml = pybergshamra.sign(sign_ctx, self._template())
        tampered = signed_xml.replace("some text", "evil text")

        verify_ctx = pybergshamra.DsigContext(km, secure_defaults=False)
        verify_ctx.set_hsm_verifier(
            pybergshamra.Pkcs11Verifier(session, "test-rsa-key", Algorithm.RSA_SHA256)
        )
        result = pybergshamra.verify(verify_ctx, tampered)
        assert bool(result) is False


# ---------------------------------------------------------------------------
# Full XML-Enc round-trip wiring a PKCS#11 op into EncContext
# ---------------------------------------------------------------------------


class TestXmlEnc:
    # RSA-OAEP key transport (SHA-1, the only OAEP digest SoftHSM2 supports)
    # wrapping an AES-256 content key.
    def _template(self):
        return (ENC_DIR / "enc-aes256-kt-rsa_oaep_sha1.tmpl").read_text()

    def _oaep_encryptor(self, session):
        return pybergshamra.Pkcs11Encryptor(
            session, "test-rsa-enc", Algorithm.RSA_OAEP,
            digest=Algorithm.SHA1, mgf=Algorithm.MGF1_SHA1,
        )

    def _oaep_decryptor(self, session):
        return pybergshamra.Pkcs11Decryptor(
            session, "test-rsa-enc", Algorithm.RSA_OAEP,
            digest=Algorithm.SHA1, mgf=Algorithm.MGF1_SHA1,
        )

    def test_hsm_encrypt_then_hsm_decrypt(self, session):
        km = pybergshamra.KeysManager()
        plaintext = b"<secret>hello hsm enc</secret>"

        # Encrypt: the AES session key is wrapped by the HSM RSA public key.
        enc_ctx = pybergshamra.EncContext(km)
        enc_ctx.set_hsm_encryptor(self._oaep_encryptor(session), [Algorithm.RSA_OAEP])
        encrypted_xml = pybergshamra.encrypt(enc_ctx, self._template(), plaintext)
        assert "CipherValue" in encrypted_xml
        assert b"hello hsm enc" not in encrypted_xml.encode()

        # Decrypt: the session key is unwrapped by the HSM RSA private key.
        dec_ctx = pybergshamra.EncContext(km)
        dec_ctx.set_hsm_decryptor(self._oaep_decryptor(session), [Algorithm.RSA_OAEP])
        recovered = pybergshamra.decrypt_to_bytes(dec_ctx, encrypted_xml)
        assert b"<secret>hello hsm enc</secret>" in recovered
