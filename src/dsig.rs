//! Digital signature verification and creation.

use pyo3::prelude::*;

use bergshamra_dsig::{
    context::DsigContext as RustDsigContext, verify::VerifiedKeyInfo as RustVerifiedKeyInfo,
    verify::VerifiedReference as RustVerifiedReference, verify::VerifyResult as RustVerifyResult,
};

use crate::errors::to_pyerr;
use crate::keys::KeysManager;

// ---------------------------------------------------------------------------
// VerifiedReference
// ---------------------------------------------------------------------------

/// Metadata about a single verified `<Reference>`.
#[pyclass(name = "VerifiedReference", skip_from_py_object)]
#[derive(Clone)]
pub struct VerifiedReference {
    uri: String,
    resolved_node_id: Option<usize>,
    digest_verified: bool,
}

#[pymethods]
impl VerifiedReference {
    /// The URI attribute from the `<Reference>` element.
    #[getter]
    fn uri(&self) -> &str {
        &self.uri
    }

    /// The resolved target node ID (if a same-document reference).
    #[getter]
    fn resolved_node_id(&self) -> Option<usize> {
        self.resolved_node_id
    }

    /// Whether this reference's digest was cryptographically verified.
    ///
    /// `False` for references that the engine could not check itself (e.g.
    /// `cid:` MIME attachments in WS-Security); the caller must verify those
    /// out of band before trusting the signature.
    #[getter]
    fn digest_verified(&self) -> bool {
        self.digest_verified
    }

    fn __repr__(&self) -> String {
        match self.resolved_node_id {
            Some(nid) => format!(
                "VerifiedReference(uri='{}', node_id={}, digest_verified={})",
                self.uri, nid, self.digest_verified
            ),
            None => format!(
                "VerifiedReference(uri='{}', digest_verified={})",
                self.uri, self.digest_verified
            ),
        }
    }
}

impl From<&RustVerifiedReference> for VerifiedReference {
    fn from(r: &RustVerifiedReference) -> Self {
        VerifiedReference {
            uri: r.uri.clone(),
            resolved_node_id: r.resolved_node.map(|nid| nid.index()),
            digest_verified: r.digest_verified,
        }
    }
}

// ---------------------------------------------------------------------------
// VerifiedKeyInfo
// ---------------------------------------------------------------------------

/// Information about the key used for verification.
#[pyclass(name = "VerifiedKeyInfo", skip_from_py_object)]
#[derive(Clone)]
pub struct VerifiedKeyInfo {
    algorithm: String,
    key_name: Option<String>,
    x509_chain_data: Vec<Vec<u8>>,
}

#[pymethods]
impl VerifiedKeyInfo {
    /// Algorithm name (e.g. "RSA", "EC-P256", "HMAC").
    #[getter]
    fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Key name (if resolved by name from KeysManager).
    #[getter]
    fn key_name(&self) -> Option<&str> {
        self.key_name.as_deref()
    }

    /// DER-encoded X.509 certificate chain (leaf first).
    #[getter]
    fn x509_chain<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, pyo3::types::PyBytes>> {
        self.x509_chain_data
            .iter()
            .map(|der| pyo3::types::PyBytes::new(py, der))
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "VerifiedKeyInfo(algorithm='{}', key_name={:?})",
            self.algorithm, self.key_name
        )
    }
}

impl From<&RustVerifiedKeyInfo> for VerifiedKeyInfo {
    fn from(ki: &RustVerifiedKeyInfo) -> Self {
        VerifiedKeyInfo {
            algorithm: ki.algorithm.clone(),
            key_name: ki.key_name.clone(),
            x509_chain_data: ki.x509_chain.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// VerifyResult
// ---------------------------------------------------------------------------

/// Result of signature verification.
///
/// Use ``bool(result)`` to check validity, or inspect properties.
#[pyclass(name = "VerifyResult", skip_from_py_object)]
#[derive(Clone)]
pub struct VerifyResult {
    valid: bool,
    reason: Option<String>,
    references_data: Option<Vec<VerifiedReference>>,
    key_info_data: Option<VerifiedKeyInfo>,
    signature_node_id_val: Option<usize>,
}

#[pymethods]
impl VerifyResult {
    /// Whether the signature is valid.
    #[getter]
    fn is_valid(&self) -> bool {
        self.valid
    }

    /// The reason for invalidity, or None if valid.
    #[getter]
    fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// The verified references, or None if invalid.
    #[getter]
    fn references(&self) -> Option<Vec<VerifiedReference>> {
        self.references_data.clone()
    }

    /// Information about the verification key, or None if invalid.
    #[getter]
    fn key_info(&self) -> Option<VerifiedKeyInfo> {
        self.key_info_data.clone()
    }

    /// The node ID of the `<Signature>` element, or None if invalid.
    #[getter]
    fn signature_node_id(&self) -> Option<usize> {
        self.signature_node_id_val
    }

    /// Whether the signature is valid but at least one `<Reference>` digest was
    /// **not** computed and verified locally (e.g. a `cid:` WS-Security MIME
    /// attachment). Such references must be verified out of band before the
    /// signature can be trusted. Always ``False`` for an invalid result.
    #[getter]
    fn has_unverified_references(&self) -> bool {
        self.valid
            && self
                .references_data
                .as_ref()
                .is_some_and(|refs| refs.iter().any(|r| !r.digest_verified))
    }

    /// Whether the signature is valid, has at least one `<Reference>`, and
    /// **every** reference digest was computed and verified locally. Returns
    /// ``False`` for an invalid result and for a valid result with no
    /// references (which provides no local digest coverage).
    #[getter]
    fn all_reference_digests_verified(&self) -> bool {
        self.valid
            && self
                .references_data
                .as_ref()
                .is_some_and(|refs| !refs.is_empty() && refs.iter().all(|r| r.digest_verified))
    }

    fn __bool__(&self) -> bool {
        self.valid
    }

    fn __repr__(&self) -> String {
        if self.valid {
            format!(
                "VerifyResult(valid=True, refs={}, sig_node={:?})",
                self.references_data.as_ref().map_or(0, |r| r.len()),
                self.signature_node_id_val,
            )
        } else {
            format!(
                "VerifyResult(valid=False, reason='{}')",
                self.reason.as_deref().unwrap_or("unknown"),
            )
        }
    }
}

impl From<RustVerifyResult> for VerifyResult {
    fn from(r: RustVerifyResult) -> Self {
        match r {
            RustVerifyResult::Valid {
                signature_node,
                references,
                key_info,
            } => VerifyResult {
                valid: true,
                reason: None,
                references_data: Some(references.iter().map(VerifiedReference::from).collect()),
                key_info_data: Some(VerifiedKeyInfo::from(&key_info)),
                signature_node_id_val: Some(signature_node.index()),
            },
            RustVerifyResult::Invalid { reason } => VerifyResult {
                valid: false,
                reason: Some(reason),
                references_data: None,
                key_info_data: None,
                signature_node_id_val: None,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// DsigContext
// ---------------------------------------------------------------------------

/// Context for XML Digital Signature operations.
///
/// Holds configuration and a KeysManager. Build one, set properties,
/// then call ``verify()`` or ``sign()``.
#[pyclass(name = "DsigContext")]
pub struct DsigContext {
    keys_manager: KeysManager,
    id_attrs: Vec<String>,
    url_maps: Vec<(String, String)>,
    hmac_min_out_len: usize,
    debug: bool,
    base_dir: Option<String>,
    insecure: bool,
    verify_keys: bool,
    verification_time: Option<String>,
    skip_time_checks: bool,
    enabled_key_data_x509: bool,
    trusted_keys_only: bool,
    strict_verification: bool,
    /// Which Rust constructor `to_rust()` starts from. When `true` the context
    /// is built from the secure-by-default `RustDsigContext::new()`, so any
    /// security defaults upstream sets beyond the fields modelled here are
    /// inherited; otherwise it starts from `new_permissive()`.
    base_secure: bool,
    hsm_signer: Option<std::sync::Arc<dyn kryptering::traits::Signer>>,
    hsm_verifier: Option<std::sync::Arc<dyn kryptering::traits::Verifier>>,
}

impl DsigContext {
    /// Build the Rust DsigContext from Python-side state.
    fn to_rust(&self) -> PyResult<RustDsigContext> {
        let mgr_guard = self
            .keys_manager
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        // Start from the same base constructor the Python profile selected, so
        // any upstream defaults not modelled as explicit fields below are
        // preserved rather than silently reset to the permissive baseline.
        let mut ctx = if self.base_secure {
            RustDsigContext::new(mgr_guard.clone())
        } else {
            RustDsigContext::new_permissive(mgr_guard.clone())
        };
        for attr in &self.id_attrs {
            ctx.add_id_attr(attr);
        }
        for (url, path) in &self.url_maps {
            ctx.add_url_map(url, path);
        }
        ctx.hmac_min_out_len = self.hmac_min_out_len;
        ctx.debug = self.debug;
        ctx.base_dir = self.base_dir.clone();
        ctx.insecure = self.insecure;
        ctx.verify_keys = self.verify_keys;
        ctx.verification_time = self.verification_time.clone();
        ctx.skip_time_checks = self.skip_time_checks;
        ctx.enabled_key_data_x509 = self.enabled_key_data_x509;
        ctx.trusted_keys_only = self.trusted_keys_only;
        ctx.strict_verification = self.strict_verification;
        if let Some(signer) = &self.hsm_signer {
            ctx.hsm_signer = Some(Box::new(crate::hsm::SharedSigner(signer.clone())));
        }
        if let Some(verifier) = &self.hsm_verifier {
            ctx.hsm_verifier = Some(Box::new(crate::hsm::SharedVerifier(verifier.clone())));
        }
        Ok(ctx)
    }
}

#[pymethods]
impl DsigContext {
    #[new]
    fn new(keys_manager: &KeysManager) -> Self {
        DsigContext {
            keys_manager: keys_manager.clone(),
            id_attrs: Vec::new(),
            url_maps: Vec::new(),
            hmac_min_out_len: 0,
            debug: false,
            base_dir: None,
            insecure: false,
            verify_keys: false,
            verification_time: None,
            skip_time_checks: false,
            enabled_key_data_x509: false,
            trusted_keys_only: false,
            strict_verification: false,
            base_secure: false,
            hsm_signer: None,
            hsm_verifier: None,
        }
    }

    /// Build a secure-by-default context, equivalent to Rust
    /// ``DsigContext::new()``: ``trusted_keys_only=True``,
    /// ``strict_verification=True``, ``hmac_min_out_len=160``, and any other
    /// secure defaults upstream sets (``to_rust()`` starts from
    /// ``RustDsigContext::new()``). Recommended for federated-identity / SAML.
    #[staticmethod]
    fn secure(keys_manager: &KeysManager) -> Self {
        let mut ctx = DsigContext::new(keys_manager);
        ctx.base_secure = true;
        ctx.trusted_keys_only = true;
        ctx.strict_verification = true;
        ctx.hmac_min_out_len = 160;
        ctx
    }

    /// Build a permissive context (mirrors Rust ``DsigContext::new_permissive()``):
    /// standard W3C behaviour with inline ``KeyInfo`` extraction enabled. This is
    /// the same configuration as the default ``DsigContext(manager)`` constructor.
    #[staticmethod]
    fn permissive(keys_manager: &KeysManager) -> Self {
        DsigContext::new(keys_manager)
    }

    /// Use an HSM-backed signer (PKCS#11) for the signing operation.
    fn set_hsm_signer(&mut self, signer: &crate::hsm::Pkcs11Signer) {
        self.hsm_signer = Some(signer.arc());
    }

    /// Use an HSM-backed verifier (PKCS#11) for the verification operation.
    fn set_hsm_verifier(&mut self, verifier: &crate::hsm::Pkcs11Verifier) {
        self.hsm_verifier = Some(verifier.arc());
    }

    /// Debug mode: print pre-digest and pre-signature data to stderr.
    #[getter]
    fn debug(&self) -> bool {
        self.debug
    }
    #[setter]
    fn set_debug(&mut self, v: bool) {
        self.debug = v;
    }

    /// Insecure mode: skip certificate validation.
    #[getter]
    fn insecure(&self) -> bool {
        self.insecure
    }
    #[setter]
    fn set_insecure(&mut self, v: bool) {
        self.insecure = v;
    }

    /// Whether to validate certificates for keys loaded from files.
    #[getter]
    fn verify_keys(&self) -> bool {
        self.verify_keys
    }
    #[setter]
    fn set_verify_keys(&mut self, v: bool) {
        self.verify_keys = v;
    }

    /// Verification time override (format: "YYYY-MM-DD+HH:MM:SS").
    #[getter]
    fn verification_time(&self) -> Option<&str> {
        self.verification_time.as_deref()
    }
    #[setter]
    fn set_verification_time(&mut self, v: Option<String>) {
        self.verification_time = v;
    }

    /// Skip X.509 time checks (NotBefore/NotAfter).
    #[getter]
    fn skip_time_checks(&self) -> bool {
        self.skip_time_checks
    }
    #[setter]
    fn set_skip_time_checks(&mut self, v: bool) {
        self.skip_time_checks = v;
    }

    /// Whether --enabled-key-data includes x509.
    #[getter]
    fn enabled_key_data_x509(&self) -> bool {
        self.enabled_key_data_x509
    }
    #[setter]
    fn set_enabled_key_data_x509(&mut self, v: bool) {
        self.enabled_key_data_x509 = v;
    }

    /// Only use pre-configured keys, skip inline KeyInfo extraction.
    #[getter]
    fn trusted_keys_only(&self) -> bool {
        self.trusted_keys_only
    }
    #[setter]
    fn set_trusted_keys_only(&mut self, v: bool) {
        self.trusted_keys_only = v;
    }

    /// Enforce strict reference target validation (anti-XSW).
    #[getter]
    fn strict_verification(&self) -> bool {
        self.strict_verification
    }
    #[setter]
    fn set_strict_verification(&mut self, v: bool) {
        self.strict_verification = v;
    }

    /// Minimum HMAC output length in bits (0 = spec default).
    #[getter]
    fn hmac_min_out_len(&self) -> usize {
        self.hmac_min_out_len
    }
    #[setter]
    fn set_hmac_min_out_len(&mut self, v: usize) {
        self.hmac_min_out_len = v;
    }

    /// Base directory for resolving relative external URIs.
    #[getter]
    fn base_dir(&self) -> Option<&str> {
        self.base_dir.as_deref()
    }
    #[setter]
    fn set_base_dir(&mut self, v: Option<String>) {
        self.base_dir = v;
    }

    /// Register an additional ID attribute name.
    fn add_id_attr(&mut self, name: &str) {
        self.id_attrs.push(name.to_owned());
    }

    /// Map a URL to a local file path for external URI resolution.
    fn add_url_map(&mut self, url: &str, file_path: &str) {
        self.url_maps.push((url.to_owned(), file_path.to_owned()));
    }
}

// ---------------------------------------------------------------------------
// Module-level functions
// ---------------------------------------------------------------------------

/// Verify a signed XML document.
///
/// Returns a VerifyResult (use ``bool(result)`` to check validity).
#[pyfunction]
pub fn verify(ctx: &DsigContext, xml: &str) -> PyResult<VerifyResult> {
    let rust_ctx = ctx.to_rust()?;
    let result = bergshamra_dsig::verify::verify(&rust_ctx, xml).map_err(to_pyerr)?;
    Ok(VerifyResult::from(result))
}

/// Verify **every** `<Signature>` element in the document, returning one
/// VerifyResult per signature in document order.
///
/// Enveloped SAML responses are commonly signed in more than one place (the
/// Response element and each Assertion). ``verify()`` reports only the first
/// signature, so a caller that must confirm a particular object is covered
/// could otherwise miss a valid signature that is not first in document order.
/// Each signature is verified independently; a per-signature failure is
/// reported as an invalid entry rather than aborting the whole call, so the
/// returned list may mix valid and invalid results.
///
/// Raises an error only for document-level failures (parse error, duplicate-ID
/// conflict, or no `<Signature>` element at all).
#[pyfunction]
pub fn verify_all(ctx: &DsigContext, xml: &str) -> PyResult<Vec<VerifyResult>> {
    let rust_ctx = ctx.to_rust()?;
    let results = bergshamra_dsig::verify::verify_all(&rust_ctx, xml).map_err(to_pyerr)?;
    Ok(results.into_iter().map(VerifyResult::from).collect())
}

/// Sign an XML template and return the signed XML string.
///
/// The template must contain a `<Signature>` skeleton with
/// `<SignedInfo>`, `<Reference>`, etc.
#[pyfunction]
pub fn sign(ctx: &DsigContext, template_xml: &str) -> PyResult<String> {
    let rust_ctx = ctx.to_rust()?;
    bergshamra_dsig::sign::sign(&rust_ctx, template_xml).map_err(to_pyerr)
}
