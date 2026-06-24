//! XML Encryption and decryption.

use pyo3::prelude::*;

use bergshamra_enc::context::EncContext as RustEncContext;

use crate::errors::to_pyerr;
use crate::keys::KeysManager;

// ---------------------------------------------------------------------------
// EncContext
// ---------------------------------------------------------------------------

/// Context for XML Encryption operations.
///
/// Holds configuration and a KeysManager. Build one, configure it,
/// then call ``encrypt()``, ``decrypt()``, or ``decrypt_to_bytes()``.
#[pyclass(name = "EncContext")]
pub struct EncContext {
    keys_manager: KeysManager,
    id_attrs: Vec<String>,
    disable_cipher_ref: bool,
    hsm_decryptor: Option<(
        std::sync::Arc<dyn kryptering::traits::Decryptor>,
        Vec<String>,
    )>,
    hsm_key_unwrapper: Option<(
        std::sync::Arc<dyn kryptering::traits::KeyWrapper>,
        Vec<String>,
    )>,
    hsm_encryptor: Option<(
        std::sync::Arc<dyn kryptering::traits::Encryptor>,
        Vec<String>,
    )>,
    hsm_key_wrapper: Option<(
        std::sync::Arc<dyn kryptering::traits::KeyWrapper>,
        Vec<String>,
    )>,
}

impl EncContext {
    /// Build the Rust EncContext from Python-side state.
    fn to_rust(&self) -> PyResult<RustEncContext> {
        let mgr_guard = self
            .keys_manager
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let mut ctx = RustEncContext::new(mgr_guard.clone());
        for attr in &self.id_attrs {
            ctx.add_id_attr(attr);
        }
        ctx.disable_cipher_reference = self.disable_cipher_ref;
        if let Some((decryptor, algs)) = &self.hsm_decryptor {
            let allowed: Vec<&str> = algs.iter().map(String::as_str).collect();
            ctx = ctx.with_hsm_decryptor(
                Box::new(crate::hsm::SharedDecryptor(decryptor.clone())),
                &allowed,
            );
        }
        if let Some((unwrapper, algs)) = &self.hsm_key_unwrapper {
            let allowed: Vec<&str> = algs.iter().map(String::as_str).collect();
            ctx = ctx.with_hsm_key_unwrapper(
                Box::new(crate::hsm::SharedKeyWrapper(unwrapper.clone())),
                &allowed,
            );
        }
        if let Some((encryptor, algs)) = &self.hsm_encryptor {
            let allowed: Vec<&str> = algs.iter().map(String::as_str).collect();
            ctx = ctx.with_hsm_encryptor(
                Box::new(crate::hsm::SharedEncryptor(encryptor.clone())),
                &allowed,
            );
        }
        if let Some((wrapper, algs)) = &self.hsm_key_wrapper {
            let allowed: Vec<&str> = algs.iter().map(String::as_str).collect();
            ctx = ctx.with_hsm_key_wrapper(
                Box::new(crate::hsm::SharedKeyWrapper(wrapper.clone())),
                &allowed,
            );
        }
        Ok(ctx)
    }
}

#[pymethods]
impl EncContext {
    #[new]
    fn new(keys_manager: &KeysManager) -> Self {
        EncContext {
            keys_manager: keys_manager.clone(),
            id_attrs: Vec::new(),
            disable_cipher_ref: false,
            hsm_decryptor: None,
            hsm_key_unwrapper: None,
            hsm_encryptor: None,
            hsm_key_wrapper: None,
        }
    }

    /// Whether CipherReference resolution is disabled.
    #[getter]
    fn disable_cipher_reference(&self) -> bool {
        self.disable_cipher_ref
    }
    #[setter]
    fn set_disable_cipher_reference(&mut self, v: bool) {
        self.disable_cipher_ref = v;
    }

    /// Register an additional ID attribute name.
    fn add_id_attr(&mut self, name: &str) {
        self.id_attrs.push(name.to_owned());
    }

    /// Decrypt the wrapped session key via an HSM (PKCS#11) private key.
    ///
    /// ``allowed_algorithms`` is the allow-list of XML-Enc key-transport URIs
    /// the HSM decryptor is permitted to handle (e.g. ``Algorithm.RSA_OAEP``).
    fn set_hsm_decryptor(
        &mut self,
        decryptor: &crate::hsm::Pkcs11Decryptor,
        allowed_algorithms: Vec<String>,
    ) {
        self.hsm_decryptor = Some((decryptor.arc(), allowed_algorithms));
    }

    /// Unwrap the session key via an HSM (PKCS#11) AES key-wrap key.
    fn set_hsm_key_unwrapper(
        &mut self,
        unwrapper: &crate::hsm::Pkcs11KeyWrapper,
        allowed_algorithms: Vec<String>,
    ) {
        self.hsm_key_unwrapper = Some((unwrapper.arc(), allowed_algorithms));
    }

    /// Encrypt the session key via an HSM (PKCS#11) public key.
    fn set_hsm_encryptor(
        &mut self,
        encryptor: &crate::hsm::Pkcs11Encryptor,
        allowed_algorithms: Vec<String>,
    ) {
        self.hsm_encryptor = Some((encryptor.arc(), allowed_algorithms));
    }

    /// Wrap the session key via an HSM (PKCS#11) AES key-wrap key.
    fn set_hsm_key_wrapper(
        &mut self,
        wrapper: &crate::hsm::Pkcs11KeyWrapper,
        allowed_algorithms: Vec<String>,
    ) {
        self.hsm_key_wrapper = Some((wrapper.arc(), allowed_algorithms));
    }
}

// ---------------------------------------------------------------------------
// Module-level functions
// ---------------------------------------------------------------------------

/// Encrypt data using an XML template.
///
/// The template must contain an ``<EncryptedData>`` element with an
/// empty ``<CipherValue>``. Returns the XML with encrypted content.
#[pyfunction]
pub fn encrypt(ctx: &EncContext, template_xml: &str, data: &[u8]) -> PyResult<String> {
    let rust_ctx = ctx.to_rust()?;
    bergshamra_enc::encrypt::encrypt(&rust_ctx, template_xml, data).map_err(to_pyerr)
}

/// Decrypt an XML document containing ``<EncryptedData>``.
///
/// Returns the decrypted XML as a string.
#[pyfunction]
pub fn decrypt(ctx: &EncContext, xml: &str) -> PyResult<String> {
    let rust_ctx = ctx.to_rust()?;
    bergshamra_enc::decrypt::decrypt(&rust_ctx, xml).map_err(to_pyerr)
}

/// Decrypt an XML document containing ``<EncryptedData>``.
///
/// Returns the raw decrypted bytes (supports non-UTF-8 content).
#[pyfunction]
pub fn decrypt_to_bytes<'py>(
    py: Python<'py>,
    ctx: &EncContext,
    xml: &str,
) -> PyResult<Bound<'py, pyo3::types::PyBytes>> {
    let rust_ctx = ctx.to_rust()?;
    let bytes = bergshamra_enc::decrypt::decrypt_to_bytes(&rust_ctx, xml).map_err(to_pyerr)?;
    Ok(pyo3::types::PyBytes::new(py, &bytes))
}
