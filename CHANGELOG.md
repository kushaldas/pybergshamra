# Changelog


## 0.6.4 [2026-07-03]

### Changed

- Updated `bergshamra` crates `0.6.3` -> `0.6.4`, which pulls in `uppsala`
  `0.8.0`. The XML parser now enforces the reserved namespace-binding rules of
  Namespaces in XML 1.0 §3 and rejects documents that bind the `xml`/`xmlns`
  namespaces illegally (such documents were never namespace-well-formed but
  were previously accepted). The release also brings faster serialization and
  fixes for `prepare_xpath()` node-arena growth and attribute `NodeId`
  stability across re-preparation. No Python API changes.


## 0.6.3 [2026-07-02]

### Changed

- Updated `bergshamra` crates `0.6.2` -> `0.6.3`, which pulls in `uppsala`
  `0.7.1`, a security-hardening release of the XML parser: XSD validation now
  fails closed on unresolved element references, invalid pattern facets, and
  malformed temporal values; namespace-sensitive attribute declarations compare
  expanded names; DTD content-model parsing observes the nesting-depth limit;
  and XSLT-generated comments/processing instructions reject markup break-out
  content. No Python API changes.


## 0.6.2 [2026-07-01]

- Updated `bergshamra` crates to `0.6.2` (trust-anchor chaining for inline
  certificates, X.509 leaf binding) and `kryptering` to `0.4.1`.
- Secure-by-default verification: added `DsigContext.secure()` and
  `DsigContext.permissive()` constructors.
- Added enveloped signing support and HSM/PKCS#11 improvements.

Older releases (0.5.1, 0.3.2) predate this changelog.
