//! Hardware Security Module (HSM) support via PKCS#11.
//!
//! Wraps the `kryptering` PKCS#11 backend so that XML-DSig signing/verification
//! and XML-Enc encryption/decryption can be performed with key material that
//! never leaves a hardware token (or SoftHSM2).
//!
//! Typical flow:
//! ```python
//! provider = pybergshamra.Pkcs11Provider("/usr/lib/softhsm/libsofthsm2.so")
//! session = provider.open_session("1234")            # user PIN
//! signer = pybergshamra.Pkcs11Signer(session, "my-rsa-key", Algorithm.RSA_SHA256)
//! ctx = pybergshamra.DsigContext(manager)
//! ctx.set_hsm_signer(signer)
//! signed_xml = pybergshamra.sign(ctx, template)
//! ```

use std::path::Path;
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use kryptering::pkcs11::{
    Pkcs11Decryptor as RustPkcs11Decryptor, Pkcs11Encryptor as RustPkcs11Encryptor,
    Pkcs11HmacSigner, Pkcs11KeyWrapper as RustPkcs11KeyWrapper,
    Pkcs11Provider as RustPkcs11Provider, Pkcs11Session as RustPkcs11Session,
    Pkcs11Signer as RustPkcs11Signer, Pkcs11Verifier as RustPkcs11Verifier,
};
use kryptering::traits::{Decryptor, Encryptor, KeyWrapper, Signer, Verifier};
use kryptering::{
    AesKeySize, EcCurve, HashAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm, OaepConfig,
    SignatureAlgorithm,
};

use bergshamra_core::algorithm as a;

use crate::errors::{kryptering_to_pyerr, AlgorithmError};

// ---------------------------------------------------------------------------
// URI → kryptering algorithm mapping
// ---------------------------------------------------------------------------

fn ec_curve_from_str(s: Option<&str>) -> PyResult<EcCurve> {
    let s = s.ok_or_else(|| {
        AlgorithmError::new_err(
            "ECDSA over HSM requires the `ec_curve` argument (\"P-256\", \"P-384\", or \"P-521\")",
        )
    })?;
    let n = s.to_ascii_uppercase().replace(['-', '_', ' '], "");
    match n.as_str() {
        "P256" | "SECP256R1" | "PRIME256V1" | "256" => Ok(EcCurve::P256),
        "P384" | "SECP384R1" | "384" => Ok(EcCurve::P384),
        "P521" | "SECP521R1" | "521" => Ok(EcCurve::P521),
        _ => Err(AlgorithmError::new_err(format!("unknown EC curve: {s}"))),
    }
}

/// Map a W3C XML-DSig signature algorithm URI to a kryptering algorithm.
///
/// ECDSA URIs do not encode the curve, so `ec_curve` must be supplied for them.
fn signature_algorithm_from_uri(uri: &str, ec_curve: Option<&str>) -> PyResult<SignatureAlgorithm> {
    use HashAlgorithm::*;
    let sa = match uri {
        a::RSA_SHA1 => SignatureAlgorithm::RsaPkcs1v15(Sha1),
        a::RSA_SHA224 => SignatureAlgorithm::RsaPkcs1v15(Sha224),
        a::RSA_SHA256 => SignatureAlgorithm::RsaPkcs1v15(Sha256),
        a::RSA_SHA384 => SignatureAlgorithm::RsaPkcs1v15(Sha384),
        a::RSA_SHA512 => SignatureAlgorithm::RsaPkcs1v15(Sha512),
        a::RSA_PSS_SHA1 => SignatureAlgorithm::RsaPss(Sha1),
        a::RSA_PSS_SHA224 => SignatureAlgorithm::RsaPss(Sha224),
        a::RSA_PSS_SHA256 => SignatureAlgorithm::RsaPss(Sha256),
        a::RSA_PSS_SHA384 => SignatureAlgorithm::RsaPss(Sha384),
        a::RSA_PSS_SHA512 => SignatureAlgorithm::RsaPss(Sha512),
        a::ECDSA_SHA1 => SignatureAlgorithm::Ecdsa(ec_curve_from_str(ec_curve)?, Sha1),
        a::ECDSA_SHA224 => SignatureAlgorithm::Ecdsa(ec_curve_from_str(ec_curve)?, Sha224),
        a::ECDSA_SHA256 => SignatureAlgorithm::Ecdsa(ec_curve_from_str(ec_curve)?, Sha256),
        a::ECDSA_SHA384 => SignatureAlgorithm::Ecdsa(ec_curve_from_str(ec_curve)?, Sha384),
        a::ECDSA_SHA512 => SignatureAlgorithm::Ecdsa(ec_curve_from_str(ec_curve)?, Sha512),
        a::EDDSA_ED25519 => SignatureAlgorithm::Ed25519,
        a::HMAC_SHA1 => SignatureAlgorithm::Hmac(Sha1),
        a::HMAC_SHA224 => SignatureAlgorithm::Hmac(Sha224),
        a::HMAC_SHA256 => SignatureAlgorithm::Hmac(Sha256),
        a::HMAC_SHA384 => SignatureAlgorithm::Hmac(Sha384),
        a::HMAC_SHA512 => SignatureAlgorithm::Hmac(Sha512),
        other => {
            return Err(AlgorithmError::new_err(format!(
                "unsupported HSM signature algorithm: {other}"
            )))
        }
    };
    Ok(sa)
}

fn hash_from_digest_uri(uri: &str) -> PyResult<HashAlgorithm> {
    let h = match uri {
        a::SHA1 => HashAlgorithm::Sha1,
        a::SHA224 => HashAlgorithm::Sha224,
        a::SHA256 => HashAlgorithm::Sha256,
        a::SHA384 => HashAlgorithm::Sha384,
        a::SHA512 => HashAlgorithm::Sha512,
        other => {
            return Err(AlgorithmError::new_err(format!(
                "unsupported OAEP digest algorithm: {other}"
            )))
        }
    };
    Ok(h)
}

fn hash_from_mgf_uri(uri: &str) -> PyResult<HashAlgorithm> {
    let h = match uri {
        a::MGF1_SHA1 => HashAlgorithm::Sha1,
        a::MGF1_SHA224 => HashAlgorithm::Sha224,
        a::MGF1_SHA256 => HashAlgorithm::Sha256,
        a::MGF1_SHA384 => HashAlgorithm::Sha384,
        a::MGF1_SHA512 => HashAlgorithm::Sha512,
        other => {
            return Err(AlgorithmError::new_err(format!(
                "unsupported MGF1 algorithm: {other}"
            )))
        }
    };
    Ok(h)
}

fn key_transport_from_uri(
    uri: &str,
    digest_uri: Option<&str>,
    mgf_uri: Option<&str>,
) -> PyResult<KeyTransportAlgorithm> {
    match uri {
        a::RSA_PKCS1 => Ok(KeyTransportAlgorithm::RsaPkcs1v15),
        a::RSA_OAEP | a::RSA_OAEP_ENC11 => {
            let digest = hash_from_digest_uri(digest_uri.unwrap_or(a::SHA256))?;
            let mgf_digest = match mgf_uri {
                Some(u) => hash_from_mgf_uri(u)?,
                None => digest,
            };
            Ok(KeyTransportAlgorithm::RsaOaep(OaepConfig {
                digest,
                mgf_digest,
            }))
        }
        other => Err(AlgorithmError::new_err(format!(
            "unsupported HSM key-transport algorithm: {other}"
        ))),
    }
}

fn key_wrap_from_uri(uri: &str) -> PyResult<KeyWrapAlgorithm> {
    let kw = match uri {
        a::KW_AES128 => KeyWrapAlgorithm::AesKw(AesKeySize::Aes128),
        a::KW_AES192 => KeyWrapAlgorithm::AesKw(AesKeySize::Aes192),
        a::KW_AES256 => KeyWrapAlgorithm::AesKw(AesKeySize::Aes256),
        a::KW_TRIPLEDES => KeyWrapAlgorithm::TripleDesKw,
        other => {
            return Err(AlgorithmError::new_err(format!(
                "unsupported HSM key-wrap algorithm: {other}"
            )))
        }
    };
    Ok(kw)
}

// ---------------------------------------------------------------------------
// Shared trait-object adapters
//
// The Python operation objects hold an `Arc<dyn Trait>`, but the bergshamra
// contexts want an owned `Box<dyn Trait>` and may be (re)built on every
// sign/verify/encrypt/decrypt call. These newtypes wrap the shared `Arc` so a
// fresh `Box` can be produced cheaply without cloning the underlying HSM
// session handle.
// ---------------------------------------------------------------------------

pub(crate) struct SharedSigner(pub(crate) Arc<dyn Signer>);
impl Signer for SharedSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
    fn sign(&self, data: &[u8]) -> kryptering::Result<Vec<u8>> {
        self.0.sign(data)
    }
}

pub(crate) struct SharedVerifier(pub(crate) Arc<dyn Verifier>);
impl Verifier for SharedVerifier {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
    fn verify(&self, data: &[u8], signature: &[u8]) -> kryptering::Result<bool> {
        self.0.verify(data, signature)
    }
}

pub(crate) struct SharedDecryptor(pub(crate) Arc<dyn Decryptor>);
impl Decryptor for SharedDecryptor {
    fn decrypt(&self, ciphertext: &[u8]) -> kryptering::Result<Vec<u8>> {
        self.0.decrypt(ciphertext)
    }
}

pub(crate) struct SharedEncryptor(pub(crate) Arc<dyn Encryptor>);
impl Encryptor for SharedEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> kryptering::Result<Vec<u8>> {
        self.0.encrypt(plaintext)
    }
}

pub(crate) struct SharedKeyWrapper(pub(crate) Arc<dyn KeyWrapper>);
impl KeyWrapper for SharedKeyWrapper {
    fn wrap(&self, key_data: &[u8]) -> kryptering::Result<Vec<u8>> {
        self.0.wrap(key_data)
    }
    fn unwrap(&self, wrapped: &[u8]) -> kryptering::Result<Vec<u8>> {
        self.0.unwrap(wrapped)
    }
}

// ---------------------------------------------------------------------------
// Provider / Session
// ---------------------------------------------------------------------------

/// A PKCS#11 provider: a loaded module backed by a single token slot.
#[pyclass(name = "Pkcs11Provider")]
pub struct Pkcs11Provider {
    inner: RustPkcs11Provider,
}

#[pymethods]
impl Pkcs11Provider {
    /// Load a PKCS#11 shared library (e.g. SoftHSM2's `libsofthsm2.so`) and
    /// bind to the first slot that has a token present.
    #[new]
    fn new(library_path: &str) -> PyResult<Self> {
        let inner =
            RustPkcs11Provider::new(Path::new(library_path)).map_err(kryptering_to_pyerr)?;
        Ok(Self { inner })
    }

    /// Open an authenticated read/write session using a UTF-8 user PIN.
    fn open_session(&self, pin: &str) -> PyResult<Pkcs11Session> {
        let session = self.inner.open_session(pin).map_err(kryptering_to_pyerr)?;
        Ok(Pkcs11Session {
            inner: Arc::new(session),
        })
    }

    /// Open an authenticated read/write session using a raw-byte PIN.
    fn open_session_bytes(&self, pin: &[u8]) -> PyResult<Pkcs11Session> {
        let session = self
            .inner
            .open_session_bytes(pin)
            .map_err(kryptering_to_pyerr)?;
        Ok(Pkcs11Session {
            inner: Arc::new(session),
        })
    }

    fn __repr__(&self) -> String {
        "Pkcs11Provider(...)".to_string()
    }
}

/// An authenticated PKCS#11 session. Pass it to the operation constructors
/// (`Pkcs11Signer`, `Pkcs11Verifier`, ...) to locate keys by label.
#[pyclass(name = "Pkcs11Session")]
pub struct Pkcs11Session {
    inner: Arc<RustPkcs11Session>,
}

#[pymethods]
impl Pkcs11Session {
    fn __repr__(&self) -> String {
        "Pkcs11Session(...)".to_string()
    }
}

// ---------------------------------------------------------------------------
// Signer / Verifier
// ---------------------------------------------------------------------------

/// Produces XML-DSig signatures using a private (or HMAC secret) key on the token.
#[pyclass(name = "Pkcs11Signer")]
pub struct Pkcs11Signer {
    inner: Arc<dyn Signer>,
}

impl Pkcs11Signer {
    pub(crate) fn arc(&self) -> Arc<dyn Signer> {
        self.inner.clone()
    }
}

#[pymethods]
impl Pkcs11Signer {
    /// Build a signer for `key_label` using the given W3C signature algorithm URI.
    ///
    /// For ECDSA algorithms, `ec_curve` ("P-256"/"P-384"/"P-521") is required
    /// because the URI alone does not identify the curve.
    #[new]
    #[pyo3(signature = (session, key_label, algorithm, ec_curve=None))]
    fn new(
        session: &Pkcs11Session,
        key_label: &str,
        algorithm: &str,
        ec_curve: Option<&str>,
    ) -> PyResult<Self> {
        let alg = signature_algorithm_from_uri(algorithm, ec_curve)?;
        let inner: Arc<dyn Signer> = if matches!(alg, SignatureAlgorithm::Hmac(_)) {
            Arc::new(
                Pkcs11HmacSigner::new(&session.inner, key_label, alg)
                    .map_err(kryptering_to_pyerr)?,
            )
        } else {
            Arc::new(
                RustPkcs11Signer::new(&session.inner, key_label, alg)
                    .map_err(kryptering_to_pyerr)?,
            )
        };
        Ok(Self { inner })
    }

    /// Sign `data` directly (mostly for testing); returns the raw signature.
    fn sign<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let sig = self.inner.sign(data).map_err(kryptering_to_pyerr)?;
        Ok(PyBytes::new(py, &sig))
    }

    fn __repr__(&self) -> String {
        "Pkcs11Signer(...)".to_string()
    }
}

/// Verifies XML-DSig signatures using a public (or HMAC secret) key on the token.
#[pyclass(name = "Pkcs11Verifier")]
pub struct Pkcs11Verifier {
    inner: Arc<dyn Verifier>,
}

impl Pkcs11Verifier {
    pub(crate) fn arc(&self) -> Arc<dyn Verifier> {
        self.inner.clone()
    }
}

#[pymethods]
impl Pkcs11Verifier {
    #[new]
    #[pyo3(signature = (session, key_label, algorithm, ec_curve=None))]
    fn new(
        session: &Pkcs11Session,
        key_label: &str,
        algorithm: &str,
        ec_curve: Option<&str>,
    ) -> PyResult<Self> {
        let alg = signature_algorithm_from_uri(algorithm, ec_curve)?;
        let inner: Arc<dyn Verifier> = if matches!(alg, SignatureAlgorithm::Hmac(_)) {
            Arc::new(
                Pkcs11HmacSigner::new(&session.inner, key_label, alg)
                    .map_err(kryptering_to_pyerr)?,
            )
        } else {
            Arc::new(
                RustPkcs11Verifier::new(&session.inner, key_label, alg)
                    .map_err(kryptering_to_pyerr)?,
            )
        };
        Ok(Self { inner })
    }

    /// Verify `signature` over `data` directly (mostly for testing).
    fn verify(&self, data: &[u8], signature: &[u8]) -> PyResult<bool> {
        self.inner
            .verify(data, signature)
            .map_err(kryptering_to_pyerr)
    }

    fn __repr__(&self) -> String {
        "Pkcs11Verifier(...)".to_string()
    }
}

// ---------------------------------------------------------------------------
// Decryptor / Encryptor (RSA key transport)
// ---------------------------------------------------------------------------

/// Decrypts a wrapped key (RSA-OAEP / RSA-PKCS1) using a private key on the token.
#[pyclass(name = "Pkcs11Decryptor")]
pub struct Pkcs11Decryptor {
    inner: Arc<dyn Decryptor>,
}

impl Pkcs11Decryptor {
    pub(crate) fn arc(&self) -> Arc<dyn Decryptor> {
        self.inner.clone()
    }
}

#[pymethods]
impl Pkcs11Decryptor {
    #[new]
    #[pyo3(signature = (session, key_label, algorithm, digest=None, mgf=None, oaep_label=None))]
    fn new(
        session: &Pkcs11Session,
        key_label: &str,
        algorithm: &str,
        digest: Option<&str>,
        mgf: Option<&str>,
        oaep_label: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let alg = key_transport_from_uri(algorithm, digest, mgf)?;
        let inner =
            RustPkcs11Decryptor::new_with_oaep_label(&session.inner, key_label, alg, oaep_label)
                .map_err(kryptering_to_pyerr)?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    fn decrypt<'py>(&self, py: Python<'py>, ciphertext: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let pt = self
            .inner
            .decrypt(ciphertext)
            .map_err(kryptering_to_pyerr)?;
        Ok(PyBytes::new(py, &pt))
    }

    fn __repr__(&self) -> String {
        "Pkcs11Decryptor(...)".to_string()
    }
}

/// Encrypts a key (RSA-OAEP / RSA-PKCS1) using a public key on the token.
#[pyclass(name = "Pkcs11Encryptor")]
pub struct Pkcs11Encryptor {
    inner: Arc<dyn Encryptor>,
}

impl Pkcs11Encryptor {
    pub(crate) fn arc(&self) -> Arc<dyn Encryptor> {
        self.inner.clone()
    }
}

#[pymethods]
impl Pkcs11Encryptor {
    #[new]
    #[pyo3(signature = (session, key_label, algorithm, digest=None, mgf=None, oaep_label=None))]
    fn new(
        session: &Pkcs11Session,
        key_label: &str,
        algorithm: &str,
        digest: Option<&str>,
        mgf: Option<&str>,
        oaep_label: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let alg = key_transport_from_uri(algorithm, digest, mgf)?;
        let inner =
            RustPkcs11Encryptor::new_with_oaep_label(&session.inner, key_label, alg, oaep_label)
                .map_err(kryptering_to_pyerr)?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    fn encrypt<'py>(&self, py: Python<'py>, plaintext: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let ct = self.inner.encrypt(plaintext).map_err(kryptering_to_pyerr)?;
        Ok(PyBytes::new(py, &ct))
    }

    fn __repr__(&self) -> String {
        "Pkcs11Encryptor(...)".to_string()
    }
}

// ---------------------------------------------------------------------------
// KeyWrapper (AES-KW)
// ---------------------------------------------------------------------------

/// Wraps/unwraps symmetric keys with an AES KEK on the token (RFC 3394).
#[pyclass(name = "Pkcs11KeyWrapper")]
pub struct Pkcs11KeyWrapper {
    inner: Arc<dyn KeyWrapper>,
}

impl Pkcs11KeyWrapper {
    pub(crate) fn arc(&self) -> Arc<dyn KeyWrapper> {
        self.inner.clone()
    }
}

#[pymethods]
impl Pkcs11KeyWrapper {
    #[new]
    fn new(session: &Pkcs11Session, key_label: &str, algorithm: &str) -> PyResult<Self> {
        let alg = key_wrap_from_uri(algorithm)?;
        let inner = RustPkcs11KeyWrapper::new(&session.inner, key_label, alg)
            .map_err(kryptering_to_pyerr)?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    fn wrap<'py>(&self, py: Python<'py>, key_data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let w = self.inner.wrap(key_data).map_err(kryptering_to_pyerr)?;
        Ok(PyBytes::new(py, &w))
    }

    fn unwrap<'py>(&self, py: Python<'py>, wrapped: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let k = self.inner.unwrap(wrapped).map_err(kryptering_to_pyerr)?;
        Ok(PyBytes::new(py, &k))
    }

    fn __repr__(&self) -> String {
        "Pkcs11KeyWrapper(...)".to_string()
    }
}
