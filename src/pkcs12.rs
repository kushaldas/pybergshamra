//! PKCS#12 (.p12/.pfx) container parsing.
//!
//! Unlike `load_pkcs12()` (which returns a single ready-to-use [`Key`]), this
//! exposes the raw contents of a PKCS#12 file: every private key (PKCS#8 DER)
//! and every certificate (DER), so callers can build full chains or inspect
//! the container.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::errors::to_pyerr;

/// The decoded contents of a PKCS#12 container.
#[pyclass(name = "Pkcs12Contents", skip_from_py_object)]
pub struct Pkcs12Contents {
    private_keys: Vec<Vec<u8>>,
    certificates: Vec<Vec<u8>>,
}

#[pymethods]
impl Pkcs12Contents {
    /// PKCS#8 DER-encoded private keys found in the container.
    #[getter]
    fn private_keys<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyBytes>> {
        self.private_keys
            .iter()
            .map(|d| PyBytes::new(py, d))
            .collect()
    }

    /// DER-encoded X.509 certificates found in the container.
    #[getter]
    fn certificates<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyBytes>> {
        self.certificates
            .iter()
            .map(|d| PyBytes::new(py, d))
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "Pkcs12Contents(private_keys={}, certificates={})",
            self.private_keys.len(),
            self.certificates.len()
        )
    }
}

/// Parse a PKCS#12 container into its raw private keys and certificates.
#[pyfunction]
pub fn parse_pkcs12(data: &[u8], password: &str) -> PyResult<Pkcs12Contents> {
    let contents = bergshamra_pkcs12::parse_pkcs12(data, password).map_err(to_pyerr)?;
    Ok(Pkcs12Contents {
        private_keys: contents
            .private_keys
            .iter()
            .map(|k| k.as_ref().to_vec())
            .collect(),
        certificates: contents.certificates,
    })
}
