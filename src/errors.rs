//! Python exception hierarchy and error conversion for bergshamra.
//!
//! Exception hierarchy:
//! ```text
//! BergshamraError (base)
//! ├── XmlError               — XmlParse, XmlStructure
//! ├── CryptoError            — Crypto, SignatureInvalid, DigestMismatch
//! ├── KeyLoadError           — Key, KeyNotFound
//! ├── AlgorithmError         — UnsupportedAlgorithm
//! ├── EncryptionError        — Encryption, Decryption
//! └── CertificateError       — Certificate
//! ```

use pyo3::create_exception;
use pyo3::prelude::*;

use bergshamra_core::Error;

// Base exception
create_exception!(pybergshamra, BergshamraError, pyo3::exceptions::PyException);

// Subclasses
create_exception!(pybergshamra, XmlError, BergshamraError);
create_exception!(pybergshamra, CryptoError, BergshamraError);
create_exception!(pybergshamra, KeyLoadError, BergshamraError);
create_exception!(pybergshamra, AlgorithmError, BergshamraError);
create_exception!(pybergshamra, EncryptionError, BergshamraError);
create_exception!(pybergshamra, CertificateError, BergshamraError);

/// Convert a `bergshamra_core::Error` into the appropriate Python exception.
pub fn to_pyerr(e: Error) -> PyErr {
    match &e {
        Error::XmlParse(_) | Error::XmlStructure(_) => XmlError::new_err(e.to_string()),
        Error::Crypto(_) | Error::SignatureInvalid(_) | Error::DigestMismatch { .. } => {
            CryptoError::new_err(e.to_string())
        }
        Error::Key(_) | Error::KeyNotFound(_) => KeyLoadError::new_err(e.to_string()),
        Error::UnsupportedAlgorithm(_) => AlgorithmError::new_err(e.to_string()),
        Error::Encryption(_) | Error::Decryption(_) => EncryptionError::new_err(e.to_string()),
        Error::Certificate(_) => CertificateError::new_err(e.to_string()),
        // Remaining variants → base BergshamraError
        Error::Canonicalization(_)
        | Error::Transform(_)
        | Error::Base64(_)
        | Error::Io(_)
        | Error::MissingElement(_)
        | Error::MissingAttribute(_)
        | Error::InvalidUri(_)
        | Error::Other(_) => BergshamraError::new_err(e.to_string()),
    }
}
