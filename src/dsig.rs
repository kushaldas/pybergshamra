//! Digital signature verification and creation.

use pyo3::exceptions::{PyRuntimeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyCapsule, PyCapsuleMethods};

use bergshamra_dsig::{
    context::DsigContext as RustDsigContext, verify::VerifiedKeyInfo as RustVerifiedKeyInfo,
    verify::VerifiedReference as RustVerifiedReference, verify::VerifyResult as RustVerifyResult,
};
use pyuppsala_interop::{DocumentCapsule, SharedDoc, DOCUMENT_CAPSULE_ABI, DOCUMENT_CAPSULE_CNAME};

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
/// Use ``bool(result)`` to check signature validity. If your application needs
/// every reference digest computed locally, also require
/// ``all_reference_digests_verified``.
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
    require_reference_digests: bool,
    /// Which Rust constructor `to_rust()` starts from. When `true` the context
    /// is built from the secure-by-default `RustDsigContext::new()`, so any
    /// security defaults upstream sets beyond the fields modelled here are
    /// inherited; otherwise it starts from `new_permissive()`.
    base_secure: bool,
    hsm_signer: Option<std::sync::Arc<dyn kryptering::traits::Signer>>,
    hsm_verifier: Option<std::sync::Arc<dyn kryptering::traits::Verifier>>,
}

impl DsigContext {
    fn from_security_defaults(
        keys_manager: &KeysManager,
        secure_defaults: bool,
        trusted_keys_only: Option<bool>,
        strict_verification: Option<bool>,
        hmac_min_out_len: Option<usize>,
        require_reference_digests: Option<bool>,
    ) -> PyResult<Self> {
        let mgr_guard = keys_manager
            .inner
            .lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let rust_ctx = if secure_defaults {
            RustDsigContext::new(mgr_guard.clone())
        } else {
            RustDsigContext::new_permissive(mgr_guard.clone())
        };

        Ok(DsigContext {
            keys_manager: keys_manager.clone(),
            id_attrs: Vec::new(),
            url_maps: Vec::new(),
            hmac_min_out_len: hmac_min_out_len.unwrap_or(rust_ctx.hmac_min_out_len),
            debug: rust_ctx.debug,
            base_dir: rust_ctx.base_dir.clone(),
            insecure: rust_ctx.insecure,
            verify_keys: rust_ctx.verify_keys,
            verification_time: rust_ctx.verification_time.clone(),
            skip_time_checks: rust_ctx.skip_time_checks,
            enabled_key_data_x509: rust_ctx.enabled_key_data_x509,
            trusted_keys_only: trusted_keys_only.unwrap_or(rust_ctx.trusted_keys_only),
            strict_verification: strict_verification.unwrap_or(rust_ctx.strict_verification),
            require_reference_digests: require_reference_digests
                .unwrap_or(rust_ctx.require_reference_digests),
            base_secure: secure_defaults,
            hsm_signer: None,
            hsm_verifier: None,
        })
    }

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
        ctx.require_reference_digests = self.require_reference_digests;
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
    #[pyo3(signature = (keys_manager, *, secure_defaults=true, trusted_keys_only=None, strict_verification=None, hmac_min_out_len=None, require_reference_digests=None))]
    fn new(
        keys_manager: &KeysManager,
        secure_defaults: bool,
        trusted_keys_only: Option<bool>,
        strict_verification: Option<bool>,
        hmac_min_out_len: Option<usize>,
        require_reference_digests: Option<bool>,
    ) -> PyResult<Self> {
        DsigContext::from_security_defaults(
            keys_manager,
            secure_defaults,
            trusted_keys_only,
            strict_verification,
            hmac_min_out_len,
            require_reference_digests,
        )
    }

    /// Build a secure-by-default context, equivalent to Rust
    /// ``DsigContext::new()``: ``trusted_keys_only=True``,
    /// ``strict_verification=True``, ``hmac_min_out_len=160``, and any other
    /// secure defaults upstream sets (``to_rust()`` starts from
    /// ``RustDsigContext::new()``). Recommended for federated-identity / SAML.
    #[staticmethod]
    fn secure(keys_manager: &KeysManager) -> PyResult<Self> {
        DsigContext::from_security_defaults(keys_manager, true, None, None, None, None)
    }

    /// Build a permissive context (mirrors Rust ``DsigContext::new_permissive()``):
    /// standard W3C behaviour with inline ``KeyInfo`` extraction enabled while
    /// still requiring local reference-digest coverage.
    /// Prefer ``DsigContext(manager, secure_defaults=False)`` when constructing
    /// permissive contexts from Python code so the opt-out is explicit.
    #[staticmethod]
    fn permissive(keys_manager: &KeysManager) -> PyResult<Self> {
        DsigContext::from_security_defaults(keys_manager, false, None, None, None, None)
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

    /// Require at least one Reference and require every Reference digest to be
    /// verified locally for validity.
    #[getter]
    fn require_reference_digests(&self) -> bool {
        self.require_reference_digests
    }
    #[setter]
    fn set_require_reference_digests(&mut self, v: bool) {
        self.require_reference_digests = v;
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

/// Extract and retain pyuppsala's shared native document handle.
///
/// Capsule pointer access is deliberately kept inside this short, GIL-held
/// section. The cloned `Arc` owns the document for the complete native
/// operation, so the temporary capsule can be dropped immediately afterwards.
fn shared_document(document: &Bound<'_, PyAny>) -> PyResult<SharedDoc> {
    let capsule_object = document
        .call_method0("_bergshamra_document_capsule")
        .map_err(|_| {
            PyTypeError::new_err(
                "document must be a pyuppsala.Document with native Bergshamra interop support",
            )
        })?;
    let capsule = capsule_object.cast::<PyCapsule>().map_err(|_| {
        PyTypeError::new_err("pyuppsala document interop method did not return a PyCapsule")
    })?;
    let pointer = capsule
        .pointer_checked(Some(DOCUMENT_CAPSULE_CNAME))?
        .cast::<DocumentCapsule>();

    // SAFETY: `pointer_checked` validated the versioned capsule name. The
    // producer constructs that capsule from a boxed `DocumentCapsule`, and the
    // capsule remains alive until after the `Arc` clone below.
    let payload = unsafe { pointer.as_ref() };
    if payload.abi != DOCUMENT_CAPSULE_ABI {
        // A wrong-ABI capsule is an incompatible input type (pyuppsala build
        // too old/new), not a runtime fault: raise TypeError like other
        // non-document inputs so callers can handle both the same way.
        return Err(PyTypeError::new_err(format!(
            "unsupported pyuppsala document capsule ABI {}; expected {} \
             (pybergshamra {} requires pyuppsala >= 0.10.0)",
            payload.abi,
            DOCUMENT_CAPSULE_ABI,
            env!("CARGO_PKG_VERSION"),
        )));
    }
    Ok(payload.shared.clone())
}

fn document_lock_error(error: impl std::fmt::Display) -> bergshamra_core::Error {
    bergshamra_core::Error::Other(format!("pyuppsala document lock failed: {error}"))
}

/// Verify the first `<Signature>` (in document order) of a signed XML document.
/// Use ``verify_all()`` to check every signature in a multi-signature document.
///
/// Returns a VerifyResult. ``bool(result)`` reports signature validity; callers
/// that require every reference digest to be checked locally should also inspect
/// ``all_reference_digests_verified`` / ``has_unverified_references``.
#[pyfunction]
pub fn verify(ctx: &DsigContext, xml: &str) -> PyResult<VerifyResult> {
    let rust_ctx = ctx.to_rust()?;
    let result = bergshamra_dsig::verify::verify(&rust_ctx, xml).map_err(to_pyerr)?;
    Ok(VerifyResult::from(result))
}

/// Verify the first `<Signature>` directly in a pyuppsala Document.
///
/// The existing DOM is borrowed through pyuppsala's native capsule, avoiding
/// XML serialization and reparsing.
#[pyfunction]
pub fn verify_document(
    py: Python<'_>,
    ctx: &DsigContext,
    document: &Bound<'_, PyAny>,
) -> PyResult<VerifyResult> {
    let shared = shared_document(document)?;
    let rust_ctx = ctx.to_rust()?;
    let result = py
        .detach(move || {
            let guard = shared.lock().map_err(document_lock_error)?;
            bergshamra_dsig::verify::verify_document(&rust_ctx, guard.doc())
        })
        .map_err(to_pyerr)?;
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

/// Verify every `<Signature>` directly in a pyuppsala Document.
#[pyfunction]
pub fn verify_all_document(
    py: Python<'_>,
    ctx: &DsigContext,
    document: &Bound<'_, PyAny>,
) -> PyResult<Vec<VerifyResult>> {
    let shared = shared_document(document)?;
    let rust_ctx = ctx.to_rust()?;
    let results = py
        .detach(move || {
            let guard = shared.lock().map_err(document_lock_error)?;
            bergshamra_dsig::verify::verify_all_document(&rust_ctx, guard.doc())
        })
        .map_err(to_pyerr)?;
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

/// Sign an existing XML-DSig template directly in a pyuppsala Document.
///
/// The document is mutated in place and must already contain empty
/// `<DigestValue>` and `<SignatureValue>` elements.
#[pyfunction]
pub fn sign_document(
    py: Python<'_>,
    ctx: &DsigContext,
    document: &Bound<'_, PyAny>,
) -> PyResult<()> {
    let shared = shared_document(document)?;
    let rust_ctx = ctx.to_rust()?;
    py.detach(move || {
        let mut guard = shared.lock().map_err(document_lock_error)?;
        guard.with_doc_mut(|_input, doc| bergshamra_dsig::sign::sign_document(&rust_ctx, doc))
    })
    .map_err(to_pyerr)
}

/// Build an enveloped `<ds:Signature>` and sign ``xml`` in one step.
///
/// This is the high-level entry point for the common case (e.g. signing SAML
/// metadata): it constructs a standard enveloped-signature template
/// (``SignedInfo`` with the given canonicalization and signature methods; a
/// single ``Reference`` to ``#{reference_id}`` — or the whole document when
/// ``reference_id`` is ``None`` — carrying the enveloped-signature and
/// exclusive-c14n transforms; ``KeyInfo``/``X509Data``), inserts it as the
/// document element's first child, and signs it with the context's key (or HSM
/// signer). The signing key is the first key in the context's ``KeysManager``.
///
/// ``cert_pem`` (one or more PEM ``CERTIFICATE`` blocks) is embedded into
/// ``X509Data``; when omitted, an empty ``<ds:X509Data/>`` is emitted and the
/// signer fills it from the signing key's certificate chain if available.
///
/// ``reference_id`` must be a raw ID value **without** a leading ``#`` (the
/// ``#`` is added when building the ``Reference`` URI); an empty string or a
/// ``#``-prefixed value raises ``ValueError``. Pass ``None`` to sign the whole
/// document (an empty-URI reference).
///
/// The common ID attribute names — ``Id``, ``ID``, ``id`` and ``AssertionID``
/// — are recognized by default, so a ``reference_id`` carried by one of those
/// attributes (such as the ``ID`` on SAML metadata) resolves with no extra
/// configuration. Do **not** call :meth:`DsigContext.add_id_attr` with one of
/// these names — double-registering a default raises a duplicate-ID error. Use
/// :meth:`DsigContext.add_id_attr` only for a *non-default* ID attribute name.
#[pyfunction]
#[pyo3(signature = (ctx, xml, *, reference_id=None, signature_method=None, digest_method=None, c14n_method=None, cert_pem=None))]
#[allow(clippy::too_many_arguments)]
pub fn sign_enveloped(
    ctx: &DsigContext,
    xml: &str,
    reference_id: Option<&str>,
    signature_method: Option<&str>,
    digest_method: Option<&str>,
    c14n_method: Option<&str>,
    cert_pem: Option<&str>,
) -> PyResult<String> {
    use bergshamra_core::algorithm;

    let sig_method = validate_signature_method(signature_method.unwrap_or(algorithm::RSA_SHA256))?;
    let dig_method = validate_digest_method(digest_method.unwrap_or(algorithm::SHA256))?;
    let c14n = validate_c14n_method(c14n_method.unwrap_or(algorithm::EXC_C14N))?;
    let ref_uri = match reference_id {
        Some("") => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "reference_id must be a non-empty ID value; pass reference_id=None \
                 to sign the whole document",
            ));
        }
        Some(id) if id.starts_with('#') => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "reference_id must be a raw ID value without a leading '#'",
            ));
        }
        Some(id) => format!("#{}", escape_xml_attr(id)),
        None => String::new(),
    };

    let key_info = build_key_info(cert_pem)?;
    let signature = format!(
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
<ds:SignedInfo>\
<ds:CanonicalizationMethod Algorithm=\"{c14n}\"/>\
<ds:SignatureMethod Algorithm=\"{sig_method}\"/>\
<ds:Reference URI=\"{ref_uri}\">\
<ds:Transforms>\
<ds:Transform Algorithm=\"{enveloped}\"/>\
<ds:Transform Algorithm=\"{c14n}\"/>\
</ds:Transforms>\
<ds:DigestMethod Algorithm=\"{dig_method}\"/>\
<ds:DigestValue></ds:DigestValue>\
</ds:Reference>\
</ds:SignedInfo>\
<ds:SignatureValue></ds:SignatureValue>\
{key_info}\
</ds:Signature>",
        enveloped = algorithm::ENVELOPED_SIGNATURE,
    );

    let template = insert_first_child_of_root(xml, &signature)?;
    let rust_ctx = ctx.to_rust()?;
    bergshamra_dsig::sign::sign_owned(&rust_ctx, template).map_err(to_pyerr)
}

/// Build and sign an enveloped signature directly in a pyuppsala Document.
///
/// The supplied document is mutated in place. No document-sized XML string is
/// created for the common enveloped-signature canonicalization path.
#[pyfunction]
#[pyo3(signature = (ctx, document, *, reference_id=None, signature_method=None, digest_method=None, c14n_method=None, cert_pem=None))]
#[allow(clippy::too_many_arguments)]
pub fn sign_enveloped_document(
    py: Python<'_>,
    ctx: &DsigContext,
    document: &Bound<'_, PyAny>,
    reference_id: Option<&str>,
    signature_method: Option<&str>,
    digest_method: Option<&str>,
    c14n_method: Option<&str>,
    cert_pem: Option<&str>,
) -> PyResult<()> {
    use bergshamra_core::algorithm;

    if reference_id == Some("") {
        return Err(PyValueError::new_err(
            "reference_id must be a non-empty ID value; pass reference_id=None to sign the whole document",
        ));
    }
    if reference_id.is_some_and(|id| id.starts_with('#')) {
        return Err(PyValueError::new_err(
            "reference_id must be a raw ID value without a leading '#'",
        ));
    }

    // Own all strings before releasing the GIL: the incoming `&str` values may
    // borrow Python string storage and must not cross the detached boundary.
    let reference_id = reference_id.map(str::to_owned);
    let signature_method = signature_method.unwrap_or(algorithm::RSA_SHA256).to_owned();
    let digest_method = digest_method.unwrap_or(algorithm::SHA256).to_owned();
    let c14n_method = c14n_method.unwrap_or(algorithm::EXC_C14N).to_owned();
    let key_info = build_key_info(cert_pem)?;
    let shared = shared_document(document)?;
    let rust_ctx = ctx.to_rust()?;

    py.detach(move || {
        let mut guard = shared.lock().map_err(document_lock_error)?;
        let options = bergshamra_dsig::sign::EnvelopedSignatureOptions::new(
            reference_id.as_deref(),
            &signature_method,
            &digest_method,
            &c14n_method,
            Some(&key_info),
        );
        guard.with_doc_mut(|_input, doc| {
            bergshamra_dsig::sign::sign_enveloped_document(&rust_ctx, doc, options)
        })
    })
    .map_err(to_pyerr)
}

fn validate_signature_method(uri: &str) -> PyResult<&str> {
    bergshamra_crypto::sign::from_uri(uri).map_err(to_pyerr)?;
    Ok(uri)
}

fn validate_digest_method(uri: &str) -> PyResult<&str> {
    bergshamra_crypto::digest::from_uri(uri).map_err(to_pyerr)?;
    Ok(uri)
}

fn validate_c14n_method(uri: &str) -> PyResult<&str> {
    if bergshamra_c14n::C14nMode::from_uri(uri).is_some() {
        Ok(uri)
    } else {
        Err(to_pyerr(bergshamra_core::Error::UnsupportedAlgorithm(
            format!("canonicalization algorithm: {uri}"),
        )))
    }
}

fn escape_xml_attr(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Build the `<ds:KeyInfo>` fragment, embedding any PEM certificates found in
/// ``cert_pem`` as `<ds:X509Certificate>` elements. With no certificate an
/// empty `<ds:X509Data/>` is emitted for the signer to populate.
fn build_key_info(cert_pem: Option<&str>) -> PyResult<String> {
    let certs: Vec<String> = match cert_pem {
        Some(pem) => {
            let certs = pem_certificate_bodies(pem)?;
            if certs.is_empty() && !pem.trim().is_empty() {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "cert_pem does not contain a CERTIFICATE block",
                ));
            }
            certs
        }
        None => Vec::new(),
    };
    if certs.is_empty() {
        return Ok("<ds:KeyInfo><ds:X509Data/></ds:KeyInfo>".to_string());
    }
    let mut x509 = String::from("<ds:KeyInfo><ds:X509Data>");
    for body in certs {
        x509.push_str("<ds:X509Certificate>");
        x509.push_str(&body);
        x509.push_str("</ds:X509Certificate>");
    }
    x509.push_str("</ds:X509Data></ds:KeyInfo>");
    Ok(x509)
}

/// Extract the base64 body of each PEM ``CERTIFICATE`` block (whitespace
/// stripped), so it can be placed inside an `<ds:X509Certificate>` element.
///
/// Each body is validated by **actually base64-decoding it** with the standard
/// engine, so malformed data — stray characters, bad padding, or a non-multiple
/// of-4 length — is rejected with a clear `ValueError` rather than being
/// embedded verbatim and failing in a less obvious way downstream.
fn pem_certificate_bodies(pem: &str) -> PyResult<Vec<String>> {
    use base64::Engine;

    let mut out = Vec::new();
    let mut body = String::new();
    let mut inside = false;
    for line in pem.lines() {
        let t = line.trim();
        if t.starts_with("-----BEGIN CERTIFICATE-----") {
            if inside {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "cert_pem contains a nested BEGIN CERTIFICATE inside an \
                     unterminated CERTIFICATE block",
                ));
            }
            inside = true;
            body.clear();
        } else if t.starts_with("-----END CERTIFICATE-----") {
            if inside {
                if body.is_empty() {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "cert_pem contains an empty CERTIFICATE block",
                    ));
                }
                base64::engine::general_purpose::STANDARD
                    .decode(&body)
                    .map_err(|e| {
                        pyo3::exceptions::PyValueError::new_err(format!(
                            "cert_pem contains invalid base64 certificate data: {e}"
                        ))
                    })?;
                out.push(std::mem::take(&mut body));
            }
            inside = false;
        } else if inside {
            for ch in t.chars() {
                if ch.is_whitespace() {
                    continue;
                }
                body.push(ch);
            }
        }
    }
    if inside {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "cert_pem contains an unterminated CERTIFICATE block",
        ));
    }
    Ok(out)
}

/// Splice ``fragment`` in as the first child of the document's root element by
/// inserting it immediately after the root element's opening tag. Uses uppsala
/// (via bergshamra-xml) to find the document element and its start-tag offset
/// in one parser pass.
fn insert_first_child_of_root(xml: &str, fragment: &str) -> PyResult<String> {
    let offset = root_start_tag_end(xml)?;
    let mut out = String::with_capacity(xml.len() + fragment.len());
    out.push_str(&xml[..offset]);
    out.push_str(fragment);
    out.push_str(&xml[offset..]);
    Ok(out)
}

/// Return the byte offset immediately after the document element's start tag.
/// Rejects self-closing document elements because they cannot host children.
fn root_start_tag_end(xml: &str) -> PyResult<usize> {
    let mut parser = bergshamra_xml::uppsala::PullParser::new(xml);

    while let Some(event) = parser
        .next_event()
        .map_err(|e| to_pyerr(bergshamra_core::Error::XmlParse(e.to_string())))?
    {
        match event {
            bergshamra_xml::uppsala::PullEvent::StartElement {
                byte_start,
                byte_end,
                ..
            } => {
                let next = parser
                    .next_event()
                    .map_err(|e| to_pyerr(bergshamra_core::Error::XmlParse(e.to_string())))?;
                if matches!(
                    next,
                    Some(bergshamra_xml::uppsala::PullEvent::EndElement {
                        byte_start: end_start,
                        ..
                    }) if end_start == byte_start
                ) {
                    return Err(to_pyerr(bergshamra_core::Error::XmlStructure(
                        "cannot envelope-sign a self-closing root element".to_string(),
                    )));
                }
                return Ok(byte_end);
            }
            _ => {}
        }
    }

    Err(to_pyerr(bergshamra_core::Error::XmlStructure(
        "document has no root element to sign".to_string(),
    )))
}
