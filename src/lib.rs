//! pybergshamra — Python bindings for the Bergshamra XML Security library.
//!
//! Provides XML-DSig verification/signing, XML-Enc encryption/decryption,
//! C14N canonicalization, key management, and crypto primitives.

use pyo3::prelude::*;

mod algorithms;
mod c14n;
mod crypto;
mod dsig;
mod enc;
mod errors;
mod keys;
mod loaders;
mod x509;

/// pybergshamra — Python bindings for Bergshamra XML Security.
///
/// XML Digital Signatures (XML-DSig), XML Encryption (XML-Enc),
/// Canonicalization (C14N), key management, and crypto primitives.
#[pymodule]
fn pybergshamra(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // ── Classes ──────────────────────────────────────────────────────
    m.add_class::<keys::KeyUsage>()?;
    m.add_class::<keys::Key>()?;
    m.add_class::<keys::KeysManager>()?;
    m.add_class::<c14n::C14nMode>()?;
    m.add_class::<dsig::DsigContext>()?;
    m.add_class::<dsig::VerifyResult>()?;
    m.add_class::<dsig::VerifiedReference>()?;
    m.add_class::<dsig::VerifiedKeyInfo>()?;
    m.add_class::<enc::EncContext>()?;
    m.add_class::<algorithms::Algorithm>()?;

    // ── Exceptions ───────────────────────────────────────────────────
    m.add(
        "BergshamraError",
        m.py().get_type::<errors::BergshamraError>(),
    )?;
    m.add("XmlError", m.py().get_type::<errors::XmlError>())?;
    m.add("CryptoError", m.py().get_type::<errors::CryptoError>())?;
    m.add("KeyLoadError", m.py().get_type::<errors::KeyLoadError>())?;
    m.add(
        "AlgorithmError",
        m.py().get_type::<errors::AlgorithmError>(),
    )?;
    m.add(
        "EncryptionError",
        m.py().get_type::<errors::EncryptionError>(),
    )?;
    m.add(
        "CertificateError",
        m.py().get_type::<errors::CertificateError>(),
    )?;

    // ── DSig functions ───────────────────────────────────────────────
    m.add_function(wrap_pyfunction!(dsig::verify, m)?)?;
    m.add_function(wrap_pyfunction!(dsig::sign, m)?)?;

    // ── Enc functions ────────────────────────────────────────────────
    m.add_function(wrap_pyfunction!(enc::encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(enc::decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(enc::decrypt_to_bytes, m)?)?;

    // ── C14N functions ───────────────────────────────────────────────
    m.add_function(wrap_pyfunction!(c14n::canonicalize, m)?)?;
    m.add_function(wrap_pyfunction!(c14n::canonicalize_subtree, m)?)?;

    // ── Crypto functions ─────────────────────────────────────────────
    m.add_function(wrap_pyfunction!(crypto::digest, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::pbkdf2_derive, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::hkdf_derive, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::concat_kdf, m)?)?;

    // ── X509 functions ───────────────────────────────────────────────
    m.add_function(wrap_pyfunction!(x509::validate_cert_chain, m)?)?;

    // ── Key loaders ──────────────────────────────────────────────────
    m.add_function(wrap_pyfunction!(loaders::load_key_file, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_key_file_with_password, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_pkcs12, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_keys_file, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_rsa_private_pem, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_rsa_public_pem, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_ec_p256_private_pem, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_ec_p384_private_pem, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_ec_p521_private_pem, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_x509_cert_pem, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_x509_cert_der, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_hmac_key, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_aes_key, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_des3_key, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_pem_auto, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_spki_pem, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_spki_der, m)?)?;
    m.add_function(wrap_pyfunction!(
        loaders::load_ed25519_private_pkcs8_der,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(loaders::load_ed25519_public_spki_der, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_x25519_private_raw, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::load_x25519_public_raw, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::parse_keys_xml, m)?)?;

    // ── KeyInfo builders ─────────────────────────────────────────────
    m.add_function(wrap_pyfunction!(loaders::build_x509_key_info, m)?)?;
    m.add_function(wrap_pyfunction!(loaders::build_x509_key_info_from_der, m)?)?;

    Ok(())
}
