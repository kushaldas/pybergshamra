//! X.509 certificate chain validation.

use pyo3::prelude::*;

use bergshamra_keys::x509::CertValidationConfig;

use crate::errors::to_pyerr;

/// Validate an X.509 certificate chain.
///
/// Verifies that the leaf certificate chains to a trusted root,
/// optionally checking time validity and CRLs.
///
/// Args:
///     leaf_der: DER-encoded leaf certificate.
///     additional_certs: Extra certificates from XML (DER-encoded).
///     trusted_certs: Trusted CA certificates (DER-encoded).
///     untrusted_certs: Untrusted intermediate certificates (DER-encoded).
///     crls: Certificate Revocation Lists (DER-encoded).
///     verification_time: Time override (format: "YYYY-MM-DD+HH:MM:SS").
///     skip_time_checks: Skip NotBefore/NotAfter validation.
///
/// Raises ``CertificateError`` on validation failure.
#[pyfunction]
#[pyo3(signature = (leaf_der, additional_certs=vec![], trusted_certs=vec![], untrusted_certs=vec![], crls=vec![], verification_time=None, skip_time_checks=false))]
pub fn validate_cert_chain(
    leaf_der: &[u8],
    additional_certs: Vec<Vec<u8>>,
    trusted_certs: Vec<Vec<u8>>,
    untrusted_certs: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
    verification_time: Option<&str>,
    skip_time_checks: bool,
) -> PyResult<()> {
    let config = CertValidationConfig {
        trusted_certs: &trusted_certs,
        untrusted_certs: &untrusted_certs,
        crls: &crls,
        verification_time,
        skip_time_checks,
    };
    bergshamra_keys::x509::validate_cert_chain(leaf_der, &additional_certs, &config)
        .map_err(to_pyerr)
}
