//! Key loading functions — wrappers around bergshamra_keys::loader and friends.

use pyo3::prelude::*;
use std::path::Path;

use crate::errors::to_pyerr;
use crate::keys::Key;
use bergshamra_keys::loader;

// ---------------------------------------------------------------------------
// File-based loaders
// ---------------------------------------------------------------------------

/// Load a key from a file (auto-detect format by extension).
#[pyfunction]
pub fn load_key_file(path: &str) -> PyResult<Key> {
    let key = loader::load_key_file(Path::new(path)).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

/// Load a key from a password-protected file.
#[pyfunction]
pub fn load_key_file_with_password(path: &str, password: &str) -> PyResult<Key> {
    let key =
        loader::load_key_file_with_password(Path::new(path), Some(password)).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

/// Load a key from PKCS#12 data with a password.
#[pyfunction]
pub fn load_pkcs12(data: &[u8], password: &str) -> PyResult<Key> {
    let key = loader::load_pkcs12(data, password).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

/// Load keys from an xmlsec keys.xml file.
#[pyfunction]
pub fn load_keys_file(path: &str) -> PyResult<Vec<Key>> {
    let keys = bergshamra_keys::keysxml::load_keys_file(Path::new(path)).map_err(to_pyerr)?;
    Ok(keys.into_iter().map(Key::from_rust).collect())
}

// ---------------------------------------------------------------------------
// RSA loaders
// ---------------------------------------------------------------------------

/// Load an RSA private key from PEM data.
#[pyfunction]
pub fn load_rsa_private_pem(pem_data: &[u8]) -> PyResult<Key> {
    let key = loader::load_rsa_private_pem(pem_data).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

/// Load an RSA public key from PEM data.
#[pyfunction]
pub fn load_rsa_public_pem(pem_data: &[u8]) -> PyResult<Key> {
    let key = loader::load_rsa_public_pem(pem_data).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

// ---------------------------------------------------------------------------
// EC loaders
// ---------------------------------------------------------------------------

/// Load an EC P-256 private key from PEM data.
#[pyfunction]
pub fn load_ec_p256_private_pem(pem_data: &[u8]) -> PyResult<Key> {
    let key = loader::load_ec_p256_private_pem(pem_data).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

/// Load an EC P-384 private key from PEM data.
#[pyfunction]
pub fn load_ec_p384_private_pem(pem_data: &[u8]) -> PyResult<Key> {
    let key = loader::load_ec_p384_private_pem(pem_data).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

/// Load an EC P-521 private key from PEM data.
#[pyfunction]
pub fn load_ec_p521_private_pem(pem_data: &[u8]) -> PyResult<Key> {
    let key = loader::load_ec_p521_private_pem(pem_data).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

// ---------------------------------------------------------------------------
// X.509 loaders
// ---------------------------------------------------------------------------

/// Load an X.509 certificate from PEM data.
#[pyfunction]
pub fn load_x509_cert_pem(pem_data: &[u8]) -> PyResult<Key> {
    let key = loader::load_x509_cert_pem(pem_data).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

/// Load an X.509 certificate from DER data.
#[pyfunction]
pub fn load_x509_cert_der(data: &[u8]) -> PyResult<Key> {
    let key = loader::load_x509_cert_der(data).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

// ---------------------------------------------------------------------------
// Symmetric loaders
// ---------------------------------------------------------------------------

/// Create an HMAC key from raw bytes.
#[pyfunction]
pub fn load_hmac_key(data: &[u8]) -> Key {
    Key::from_rust(loader::load_hmac_key(data))
}

/// Create an AES key from raw bytes.
#[pyfunction]
pub fn load_aes_key(data: &[u8]) -> PyResult<Key> {
    let key = loader::load_aes_key(data).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

/// Create a 3DES key from raw bytes.
#[pyfunction]
pub fn load_des3_key(data: &[u8]) -> PyResult<Key> {
    let key = loader::load_des3_key(data).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

// ---------------------------------------------------------------------------
// Auto-detect / generic PEM loaders
// ---------------------------------------------------------------------------

/// Auto-detect PEM type and load the key.
#[pyfunction]
#[pyo3(signature = (pem_data, password=None))]
pub fn load_pem_auto(pem_data: &[u8], password: Option<&str>) -> PyResult<Key> {
    let key = loader::load_pem_auto(pem_data, password).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

/// Load a public key from SPKI PEM data.
#[pyfunction]
pub fn load_spki_pem(pem_data: &[u8]) -> PyResult<Key> {
    let key = loader::load_spki_pem(pem_data).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

/// Load a public key from SPKI DER data.
#[pyfunction]
pub fn load_spki_der(data: &[u8]) -> PyResult<Key> {
    let key = loader::load_spki_der(data).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

// ---------------------------------------------------------------------------
// Ed25519 loaders
// ---------------------------------------------------------------------------

/// Load an Ed25519 private key from PKCS#8 DER data.
#[pyfunction]
pub fn load_ed25519_private_pkcs8_der(data: &[u8]) -> PyResult<Key> {
    let key = loader::load_ed25519_private_pkcs8_der(data).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

/// Load an Ed25519 public key from SPKI DER data.
#[pyfunction]
pub fn load_ed25519_public_spki_der(data: &[u8]) -> PyResult<Key> {
    let key = loader::load_ed25519_public_spki_der(data).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

// ---------------------------------------------------------------------------
// X25519 loaders
// ---------------------------------------------------------------------------

/// Load an X25519 private key from raw 32-byte data.
#[pyfunction]
pub fn load_x25519_private_raw(data: &[u8]) -> PyResult<Key> {
    let key = loader::load_x25519_private_raw(data).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

/// Load an X25519 public key from raw 32-byte data.
#[pyfunction]
pub fn load_x25519_public_raw(data: &[u8]) -> PyResult<Key> {
    let key = loader::load_x25519_public_raw(data).map_err(to_pyerr)?;
    Ok(Key::from_rust(key))
}

// ---------------------------------------------------------------------------
// XML keys
// ---------------------------------------------------------------------------

/// Parse keys from an xmlsec keys.xml string.
#[pyfunction]
pub fn parse_keys_xml(xml: &str) -> PyResult<Vec<Key>> {
    let keys = bergshamra_keys::keysxml::parse_keys_xml(xml).map_err(to_pyerr)?;
    Ok(keys.into_iter().map(Key::from_rust).collect())
}

// ---------------------------------------------------------------------------
// X509 KeyInfo builders
// ---------------------------------------------------------------------------

/// Build a <KeyInfo><X509Data> XML fragment from base64-encoded certificates.
#[pyfunction]
pub fn build_x509_key_info(certs_b64: Vec<String>) -> String {
    let refs: Vec<&str> = certs_b64.iter().map(|s| s.as_str()).collect();
    bergshamra_keys::build_x509_key_info(&refs)
}

/// Build a <KeyInfo><X509Data> XML fragment from DER-encoded certificates.
#[pyfunction]
pub fn build_x509_key_info_from_der(certs_der: Vec<Vec<u8>>) -> String {
    bergshamra_keys::build_x509_key_info_from_der(&certs_der)
}
