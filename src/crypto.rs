//! Cryptographic primitives: digest, PBKDF2, HKDF, ConcatKDF.

use pyo3::prelude::*;

use crate::errors::to_pyerr;

/// Compute a one-shot message digest.
///
/// ``algorithm_uri`` is a W3C algorithm URI (e.g. ``Algorithm.SHA256``).
/// Returns the digest bytes.
#[pyfunction]
pub fn digest<'py>(
    py: Python<'py>,
    algorithm_uri: &str,
    data: &[u8],
) -> PyResult<Bound<'py, pyo3::types::PyBytes>> {
    let result = bergshamra_crypto::digest::digest(algorithm_uri, data).map_err(to_pyerr)?;
    Ok(pyo3::types::PyBytes::new(py, &result))
}

/// Derive a key using PBKDF2 (RFC 8018).
///
/// Args:
///     password: The password/secret bytes.
///     salt: Salt bytes.
///     iteration_count: Number of iterations.
///     key_length: Desired output key length in bytes.
///     prf_uri: PRF algorithm URI (e.g. ``Algorithm.HMAC_SHA256``).
///
/// Returns the derived key bytes.
#[pyfunction]
pub fn pbkdf2_derive<'py>(
    py: Python<'py>,
    password: &[u8],
    salt: &[u8],
    iteration_count: u32,
    key_length: usize,
    prf_uri: &str,
) -> PyResult<Bound<'py, pyo3::types::PyBytes>> {
    let params = bergshamra_crypto::kdf::Pbkdf2Params {
        prf_uri: prf_uri.to_owned(),
        salt: salt.to_vec(),
        iteration_count,
        key_length,
    };
    let result = bergshamra_crypto::kdf::pbkdf2_derive(password, &params).map_err(to_pyerr)?;
    Ok(pyo3::types::PyBytes::new(py, &result))
}

/// Derive a key using HKDF (RFC 5869).
///
/// Args:
///     shared_secret: Input keying material (IKM).
///     key_length: Desired output key length in bytes.
///     prf_uri: PRF algorithm URI (default: HMAC-SHA256).
///     salt: Optional salt bytes.
///     info: Optional context/info bytes.
///
/// Returns the derived key bytes.
#[pyfunction]
#[pyo3(signature = (shared_secret, key_length, prf_uri=None, salt=None, info=None))]
pub fn hkdf_derive<'py>(
    py: Python<'py>,
    shared_secret: &[u8],
    key_length: usize,
    prf_uri: Option<&str>,
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
) -> PyResult<Bound<'py, pyo3::types::PyBytes>> {
    let params = bergshamra_crypto::kdf::HkdfParams {
        prf_uri: prf_uri.map(|s| s.to_owned()),
        salt: salt.map(|s| s.to_vec()),
        info: info.map(|i| i.to_vec()),
        key_length_bits: 0, // Use key_length parameter directly
    };
    let result = bergshamra_crypto::kdf::hkdf_derive(shared_secret, key_length, &params)
        .map_err(to_pyerr)?;
    Ok(pyo3::types::PyBytes::new(py, &result))
}

/// Derive a key using ConcatKDF (NIST SP 800-56A).
///
/// Args:
///     shared_secret: The shared secret bytes (Z).
///     key_length: Desired output key length in bytes.
///     digest_uri: Digest algorithm URI (default: SHA-256).
///     algorithm_id: Optional AlgorithmID bytes.
///     party_u_info: Optional PartyUInfo bytes.
///     party_v_info: Optional PartyVInfo bytes.
///
/// Returns the derived key bytes.
#[pyfunction]
#[pyo3(signature = (shared_secret, key_length, digest_uri=None, algorithm_id=None, party_u_info=None, party_v_info=None))]
pub fn concat_kdf<'py>(
    py: Python<'py>,
    shared_secret: &[u8],
    key_length: usize,
    digest_uri: Option<&str>,
    algorithm_id: Option<&[u8]>,
    party_u_info: Option<&[u8]>,
    party_v_info: Option<&[u8]>,
) -> PyResult<Bound<'py, pyo3::types::PyBytes>> {
    let params = bergshamra_crypto::kdf::ConcatKdfParams {
        digest_uri: digest_uri.map(|s| s.to_owned()),
        algorithm_id: algorithm_id.map(|b| b.to_vec()),
        party_u_info: party_u_info.map(|b| b.to_vec()),
        party_v_info: party_v_info.map(|b| b.to_vec()),
    };
    let result =
        bergshamra_crypto::kdf::concat_kdf(shared_secret, key_length, &params).map_err(to_pyerr)?;
    Ok(pyo3::types::PyBytes::new(py, &result))
}
