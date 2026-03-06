//! C14N mode enum and canonicalization functions.

use pyo3::prelude::*;

use bergshamra_c14n::{canonicalize as rust_canonicalize, C14nMode as RustC14nMode};
use bergshamra_xml::document::XmlDocument;
use bergshamra_xml::nodeset::NodeSet;

use crate::errors::to_pyerr;

// ---------------------------------------------------------------------------
// C14nMode enum
// ---------------------------------------------------------------------------

/// XML Canonicalization mode.
#[pyclass(name = "C14nMode", eq, eq_int, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum C14nMode {
    Inclusive = 0,
    InclusiveWithComments = 1,
    Inclusive11 = 2,
    Inclusive11WithComments = 3,
    Exclusive = 4,
    ExclusiveWithComments = 5,
}

impl From<C14nMode> for RustC14nMode {
    fn from(m: C14nMode) -> Self {
        match m {
            C14nMode::Inclusive => RustC14nMode::Inclusive,
            C14nMode::InclusiveWithComments => RustC14nMode::InclusiveWithComments,
            C14nMode::Inclusive11 => RustC14nMode::Inclusive11,
            C14nMode::Inclusive11WithComments => RustC14nMode::Inclusive11WithComments,
            C14nMode::Exclusive => RustC14nMode::Exclusive,
            C14nMode::ExclusiveWithComments => RustC14nMode::ExclusiveWithComments,
        }
    }
}

impl From<RustC14nMode> for C14nMode {
    fn from(m: RustC14nMode) -> Self {
        match m {
            RustC14nMode::Inclusive => C14nMode::Inclusive,
            RustC14nMode::InclusiveWithComments => C14nMode::InclusiveWithComments,
            RustC14nMode::Inclusive11 => C14nMode::Inclusive11,
            RustC14nMode::Inclusive11WithComments => C14nMode::Inclusive11WithComments,
            RustC14nMode::Exclusive => C14nMode::Exclusive,
            RustC14nMode::ExclusiveWithComments => C14nMode::ExclusiveWithComments,
        }
    }
}

#[pymethods]
impl C14nMode {
    /// The W3C algorithm URI for this mode.
    #[getter]
    fn uri(&self) -> &'static str {
        RustC14nMode::from(*self).uri()
    }

    /// Whether this mode includes comments.
    #[getter]
    fn with_comments(&self) -> bool {
        matches!(
            self,
            C14nMode::InclusiveWithComments
                | C14nMode::Inclusive11WithComments
                | C14nMode::ExclusiveWithComments
        )
    }

    /// Whether this mode uses exclusive canonicalization.
    #[getter]
    fn is_exclusive(&self) -> bool {
        RustC14nMode::from(*self).is_exclusive()
    }

    /// Look up a C14nMode from its W3C algorithm URI.
    #[staticmethod]
    fn from_uri(uri: &str) -> Option<C14nMode> {
        RustC14nMode::from_uri(uri).map(C14nMode::from)
    }

    fn __repr__(&self) -> String {
        let name = match self {
            C14nMode::Inclusive => "Inclusive",
            C14nMode::InclusiveWithComments => "InclusiveWithComments",
            C14nMode::Inclusive11 => "Inclusive11",
            C14nMode::Inclusive11WithComments => "Inclusive11WithComments",
            C14nMode::Exclusive => "Exclusive",
            C14nMode::ExclusiveWithComments => "ExclusiveWithComments",
        };
        format!("C14nMode.{}", name)
    }
}

// ---------------------------------------------------------------------------
// canonicalize — whole document
// ---------------------------------------------------------------------------

/// Canonicalize an XML document.
///
/// Args:
///     xml: The XML string.
///     mode: The C14N mode.
///     inclusive_prefixes: Optional list of namespace prefixes to force
///         visibly-utilized in exclusive C14N.
///
/// Returns:
///     The canonicalized XML as bytes.
#[pyfunction]
#[pyo3(signature = (xml, mode, inclusive_prefixes=None))]
pub fn canonicalize<'py>(
    py: Python<'py>,
    xml: &str,
    mode: C14nMode,
    inclusive_prefixes: Option<Vec<String>>,
) -> PyResult<Bound<'py, pyo3::types::PyBytes>> {
    let prefixes = inclusive_prefixes.unwrap_or_default();
    let result =
        rust_canonicalize(xml, RustC14nMode::from(mode), None, &prefixes).map_err(to_pyerr)?;
    Ok(pyo3::types::PyBytes::new(py, &result))
}

// ---------------------------------------------------------------------------
// canonicalize_subtree — canonicalize a specific element by ID
// ---------------------------------------------------------------------------

/// Canonicalize a subtree identified by an element ID.
///
/// Parses the XML, locates the element with the given ID attribute value,
/// builds a node set from that subtree, and canonicalizes it.
///
/// Args:
///     xml: The XML string.
///     element_id: The ID attribute value of the target element.
///     mode: The C14N mode.
///     inclusive_prefixes: Optional list of namespace prefixes.
///
/// Returns:
///     The canonicalized subtree as bytes.
#[pyfunction]
#[pyo3(signature = (xml, element_id, mode, inclusive_prefixes=None))]
pub fn canonicalize_subtree<'py>(
    py: Python<'py>,
    xml: &str,
    element_id: &str,
    mode: C14nMode,
    inclusive_prefixes: Option<Vec<String>>,
) -> PyResult<Bound<'py, pyo3::types::PyBytes>> {
    let prefixes = inclusive_prefixes.unwrap_or_default();

    // Parse with bergshamra_xml to get ID map and inner roxmltree doc
    let xml_doc = XmlDocument::parse(xml.to_string()).map_err(to_pyerr)?;
    let doc = xml_doc.parse_doc().map_err(to_pyerr)?;
    let id_map = xml_doc.build_id_map(&doc);
    let node_id = XmlDocument::find_by_id(&doc, &id_map, element_id).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "Element with ID '{}' not found",
            element_id
        ))
    })?;

    // Build subtree node set
    let node_set = NodeSet::tree_without_comments(node_id, &doc);

    // Canonicalize with node set
    let result = bergshamra_c14n::canonicalize_doc(
        &doc,
        RustC14nMode::from(mode),
        Some(&node_set),
        &prefixes,
    )
    .map_err(to_pyerr)?;
    Ok(pyo3::types::PyBytes::new(py, &result))
}
