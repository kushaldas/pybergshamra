//! Python wrappers for Key, KeyUsage, and KeysManager.

use pyo3::prelude::*;
use std::sync::{Arc, Mutex};

use bergshamra_keys::{Key as RustKey, KeyUsage as RustKeyUsage, KeysManager as RustKeysManager};

// ---------------------------------------------------------------------------
// KeyUsage
// ---------------------------------------------------------------------------

/// Key usage mode.
#[pyclass(name = "KeyUsage", eq, eq_int, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyUsage {
    Sign = 0,
    Verify = 1,
    Encrypt = 2,
    Decrypt = 3,
    Any = 4,
}

impl From<RustKeyUsage> for KeyUsage {
    fn from(u: RustKeyUsage) -> Self {
        match u {
            RustKeyUsage::Sign => KeyUsage::Sign,
            RustKeyUsage::Verify => KeyUsage::Verify,
            RustKeyUsage::Encrypt => KeyUsage::Encrypt,
            RustKeyUsage::Decrypt => KeyUsage::Decrypt,
            RustKeyUsage::Any => KeyUsage::Any,
        }
    }
}

impl From<KeyUsage> for RustKeyUsage {
    fn from(u: KeyUsage) -> Self {
        match u {
            KeyUsage::Sign => RustKeyUsage::Sign,
            KeyUsage::Verify => RustKeyUsage::Verify,
            KeyUsage::Encrypt => RustKeyUsage::Encrypt,
            KeyUsage::Decrypt => RustKeyUsage::Decrypt,
            KeyUsage::Any => RustKeyUsage::Any,
        }
    }
}

// ---------------------------------------------------------------------------
// Key
// ---------------------------------------------------------------------------

/// A cryptographic key (RSA, EC, HMAC, AES, Ed25519, X25519, PQ, etc.).
#[pyclass(name = "Key", skip_from_py_object)]
#[derive(Clone)]
pub struct Key {
    pub(crate) inner: Arc<Mutex<RustKey>>,
}

impl Key {
    /// Wrap a Rust Key into a Python Key.
    pub(crate) fn from_rust(key: RustKey) -> Self {
        Key {
            inner: Arc::new(Mutex::new(key)),
        }
    }
}

#[pymethods]
impl Key {
    /// The key name, or None.
    #[getter]
    fn name(&self) -> PyResult<Option<String>> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(guard.name.clone())
    }

    /// Set the key name.
    #[setter]
    fn set_name(&self, name: Option<String>) -> PyResult<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        guard.name = name;
        Ok(())
    }

    /// The key usage mode.
    #[getter]
    fn usage(&self) -> PyResult<KeyUsage> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(KeyUsage::from(guard.usage))
    }

    /// Set the key usage mode.
    #[setter]
    fn set_usage(&self, usage: KeyUsage) -> PyResult<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        guard.usage = RustKeyUsage::from(usage);
        Ok(())
    }

    /// The algorithm name (e.g. "RSA", "EC-P256", "HMAC").
    #[getter]
    fn algorithm_name(&self) -> PyResult<String> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(guard.algorithm_name().to_string())
    }

    /// Whether this key contains private key material.
    #[getter]
    fn has_private_key(&self) -> PyResult<bool> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(guard.has_private_key())
    }

    /// The DER-encoded X.509 certificate chain, if present.
    #[getter]
    fn x509_chain<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, pyo3::types::PyBytes>>> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(guard
            .x509_chain
            .iter()
            .map(|der| pyo3::types::PyBytes::new(py, der))
            .collect())
    }

    /// Return the SPKI DER encoding if available, or None.
    fn to_spki_der<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Option<Bound<'py, pyo3::types::PyBytes>>> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(guard
            .to_spki_der()
            .map(|v| pyo3::types::PyBytes::new(py, &v)))
    }

    /// Return the raw symmetric key bytes (HMAC/AES/DES3), or None.
    fn symmetric_key_bytes<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Option<Bound<'py, pyo3::types::PyBytes>>> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(guard
            .symmetric_key_bytes()
            .map(|b| pyo3::types::PyBytes::new(py, b)))
    }

    /// Return the uncompressed EC public key bytes, or None.
    fn ec_public_key_bytes<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Option<Bound<'py, pyo3::types::PyBytes>>> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(guard
            .ec_public_key_bytes()
            .map(|b| pyo3::types::PyBytes::new(py, &b)))
    }

    /// Return the X25519 public key bytes (32 bytes), or None.
    fn x25519_public_key_bytes<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Option<Bound<'py, pyo3::types::PyBytes>>> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(guard
            .x25519_public_key_bytes()
            .map(|b| pyo3::types::PyBytes::new(py, b)))
    }

    /// Return the X25519 private key bytes (32 bytes), or None.
    fn x25519_private_key_bytes<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Option<Bound<'py, pyo3::types::PyBytes>>> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(guard
            .x25519_private_key_bytes()
            .map(|b| pyo3::types::PyBytes::new(py, b)))
    }

    /// Return the KeyValue XML fragment, or None.
    #[pyo3(signature = (prefix="ds"))]
    fn to_key_value_xml(&self, prefix: &str) -> PyResult<Option<String>> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(guard.to_key_value_xml(prefix))
    }

    fn __repr__(&self) -> PyResult<String> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let name = guard.name.as_deref().unwrap_or("(unnamed)");
        Ok(format!(
            "Key(name='{}', algorithm='{}', usage={:?})",
            name,
            guard.algorithm_name(),
            guard.usage,
        ))
    }
}

// ---------------------------------------------------------------------------
// KeysManager
// ---------------------------------------------------------------------------

/// Key store for managing cryptographic keys and certificates.
#[pyclass(name = "KeysManager", skip_from_py_object)]
#[derive(Clone)]
pub struct KeysManager {
    pub(crate) inner: Arc<Mutex<RustKeysManager>>,
}

#[pymethods]
impl KeysManager {
    #[new]
    fn new() -> Self {
        KeysManager {
            inner: Arc::new(Mutex::new(RustKeysManager::new())),
        }
    }

    /// Add a key to the manager.
    fn add_key(&self, key: &Key) -> PyResult<()> {
        let k = key
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let mut mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        mgr.add_key(k.clone());
        Ok(())
    }

    /// Insert a key at the front (becomes the first key).
    fn insert_key_first(&self, key: &Key) -> PyResult<()> {
        let k = key
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let mut mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        mgr.insert_key_first(k.clone());
        Ok(())
    }

    /// Return the first key, or None.
    fn first_key(&self) -> PyResult<Option<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.first_key().ok().map(|k| Key::from_rust(k.clone())))
    }

    /// Return all keys as a list.
    fn keys(&self) -> PyResult<Vec<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.keys().map(|k| Key::from_rust(k.clone())).collect())
    }

    /// Find a key by name.
    fn find_by_name(&self, name: &str) -> PyResult<Option<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.find_by_name(name).map(|k| Key::from_rust(k.clone())))
    }

    /// Find a key by usage.
    fn find_by_usage(&self, usage: KeyUsage) -> PyResult<Option<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr
            .find_by_usage(RustKeyUsage::from(usage))
            .map(|k| Key::from_rust(k.clone())))
    }

    /// Find the first RSA key.
    fn find_rsa(&self) -> PyResult<Option<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.find_rsa().map(|k| Key::from_rust(k.clone())))
    }

    /// Find the first RSA key with private material.
    fn find_rsa_private(&self) -> PyResult<Option<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.find_rsa_private().map(|k| Key::from_rust(k.clone())))
    }

    /// Find the first HMAC key.
    fn find_hmac(&self) -> PyResult<Option<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.find_hmac().map(|k| Key::from_rust(k.clone())))
    }

    /// Find the first AES key.
    fn find_aes(&self) -> PyResult<Option<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.find_aes().map(|k| Key::from_rust(k.clone())))
    }

    /// Find the first AES key matching the given size in bytes.
    fn find_aes_by_size(&self, size_bytes: usize) -> PyResult<Option<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr
            .find_aes_by_size(size_bytes)
            .map(|k| Key::from_rust(k.clone())))
    }

    /// Find the first 3DES key.
    fn find_des3(&self) -> PyResult<Option<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.find_des3().map(|k| Key::from_rust(k.clone())))
    }

    /// Find the first EC P-256 key.
    fn find_ec_p256(&self) -> PyResult<Option<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.find_ec_p256().map(|k| Key::from_rust(k.clone())))
    }

    /// Find the first EC P-384 key.
    fn find_ec_p384(&self) -> PyResult<Option<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.find_ec_p384().map(|k| Key::from_rust(k.clone())))
    }

    /// Find the first EC P-521 key.
    fn find_ec_p521(&self) -> PyResult<Option<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.find_ec_p521().map(|k| Key::from_rust(k.clone())))
    }

    /// Find the first Ed25519 key.
    fn find_ed25519(&self) -> PyResult<Option<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.find_ed25519().map(|k| Key::from_rust(k.clone())))
    }

    /// Find the first X25519 key.
    fn find_x25519(&self) -> PyResult<Option<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.find_x25519().map(|k| Key::from_rust(k.clone())))
    }

    /// Find the first post-quantum key.
    fn find_pq(&self) -> PyResult<Option<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.find_pq().map(|k| Key::from_rust(k.clone())))
    }

    /// Find the first DH key.
    fn find_dh(&self) -> PyResult<Option<Key>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.find_dh().map(|k| Key::from_rust(k.clone())))
    }

    /// Add a trusted DER-encoded X.509 certificate.
    fn add_trusted_cert(&self, der: &[u8]) -> PyResult<()> {
        let mut mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        mgr.add_trusted_cert(der.to_vec());
        Ok(())
    }

    /// Add an untrusted DER-encoded X.509 certificate.
    fn add_untrusted_cert(&self, der: &[u8]) -> PyResult<()> {
        let mut mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        mgr.add_untrusted_cert(der.to_vec());
        Ok(())
    }

    /// Add a DER-encoded CRL.
    fn add_crl(&self, der: &[u8]) -> PyResult<()> {
        let mut mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        mgr.add_crl(der.to_vec());
        Ok(())
    }

    /// Return the trusted certificates as a list of DER bytes.
    fn trusted_certs<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Vec<Bound<'py, pyo3::types::PyBytes>>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr
            .trusted_certs()
            .iter()
            .map(|der| pyo3::types::PyBytes::new(py, der))
            .collect())
    }

    /// Return the untrusted certificates as a list of DER bytes.
    fn untrusted_certs<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Vec<Bound<'py, pyo3::types::PyBytes>>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr
            .untrusted_certs()
            .iter()
            .map(|der| pyo3::types::PyBytes::new(py, der))
            .collect())
    }

    /// Return the CRLs as a list of DER bytes.
    fn crls<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, pyo3::types::PyBytes>>> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr
            .crls()
            .iter()
            .map(|der| pyo3::types::PyBytes::new(py, der))
            .collect())
    }

    /// Whether the manager has any trusted certificates.
    fn has_trusted_certs(&self) -> PyResult<bool> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.has_trusted_certs())
    }

    fn __len__(&self) -> PyResult<usize> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(mgr.len())
    }

    fn __bool__(&self) -> PyResult<bool> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(!mgr.is_empty())
    }

    fn __repr__(&self) -> PyResult<String> {
        let mgr = self
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(format!(
            "KeysManager(keys={}, trusted_certs={})",
            mgr.len(),
            mgr.trusted_certs().len()
        ))
    }
}
