# Changelog


## 0.7.0 [2026-07-06]

### Security

- Updated all `bergshamra` crates `0.6.4` -> `0.7.0`, which pulls in
  `uppsala` `0.9.0`.
- XML-DSig verification now requires local `<Reference>` digest coverage by
  default. A valid signature must contain at least one reference and every
  reference digest must be computed and verified locally. Callers that verify
  detached content out of band can opt out with
  `DsigContext(..., require_reference_digests=False)` or by setting
  `ctx.require_reference_digests = False`.
- `DsigContext(manager, secure_defaults=False)` and
  `DsigContext.permissive(manager)` still opt out of inline-KeyInfo and relaxed
  structural/HMAC defaults, but they now continue to require local reference
  digest coverage unless `require_reference_digests=False` is passed.
- XML-DSig signing and verification now reject unsafe local `<Reference URI>`
  fallback values: scheme URLs, absolute paths, and parent-traversing paths are
  rejected. Simple relative detached files remain supported, and explicit
  mappings should use `DsigContext.add_url_map()`.
- Verifier debug output from upstream `bergshamra` now redacts detached
  reference bytes.
- XML-DSig verification now rejects raw inline `<KeyValue>` and
  `<DEREncodedKeyValue>` signing keys when trust anchors are configured. Inline
  `<X509Data>` remains supported, but its chain must validate to a configured
  anchor.
- Duplicate XML ID values are now rejected instead of silently overwriting
  earlier entries in the ID map. This affects DSig verification, DSig signing
  reference resolution, and `canonicalize_subtree()`.
- XML-Enc PBKDF2 parameters now enforce an upstream iteration-count cap before
  invoking PBKDF2.
- Malformed RSA `KeyValue` CryptoBinary values now return parse errors instead
  of panicking on odd-length hex input.
- The `uppsala` `0.9.0` parser and XML stack add additional hostile-input
  hardening: pull-parser errors fuse fail-closed, XPath rejects trailing tokens
  and counts flat operator chains against expression-depth limits, XSLT
  computed element/attribute names are QName-validated, XSD identity-constraint
  lookup avoids quadratic scans, duplicate top-level XSD model groups are
  rejected, optional XSLT result/output byte caps are available upstream, and
  retained XML declaration encodings from `parse_bytes()` are normalized to
  `UTF-8`.

### Added

- Added Python `DsigContext.require_reference_digests` constructor keyword,
  property getter, and property setter.
- Added typing and documentation for `require_reference_digests` in
  `pybergshamra.pyi` and the Sphinx API docs.

### Changed

- Package metadata is now `0.7.0`.
- `DsigContext` now delegates its default values to the upstream Rust
  `bergshamra` constructors instead of duplicating defaults in the Python
  binding. This keeps future upstream secure-default changes visible to
  pybergshamra while still preserving Python keyword overrides.
- `sign_enveloped()` now passes the generated template to upstream
  `bergshamra_dsig::sign::sign_owned()`, avoiding an extra template clone.
- `sign_enveloped()` now uses `uppsala` pull-parser metadata to locate the
  document element start tag in one parser pass before inserting the generated
  `<ds:Signature>`. Self-closing root elements are still rejected because they
  cannot host the enveloped signature child.
- `canonicalize_subtree()` now propagates duplicate-ID errors from the upstream
  ID-map builder.
- Documentation and examples were updated for the new default reference-digest
  policy: with the default context, a truthy `VerifyResult` already includes
  local reference-digest coverage.
- API docs now spell out that `verify()` checks the first signature in document
  order and `verify_all()` checks every signature independently, with
  per-signature failures reported as invalid entries.
- `DsigContext.add_id_attr()` docs now emphasize that common ID attributes
  `Id`, `ID`, `id`, and `AssertionID` are already recognized by default and
  should not be registered again.

### Compatibility notes

- Applications that previously accepted signatures with detached references
  whose digest bytes are verified outside pybergshamra must explicitly set
  `require_reference_digests=False`.
- Applications that configured trust anchors and also relied on raw inline
  `KeyValue`/`DEREncodedKeyValue` signatures should switch those documents to
  inline `X509Data` with a chain to a configured trust anchor.
- Re-registering a default ID attribute can now surface duplicate-ID errors;
  call `add_id_attr()` only for non-default ID attribute names.


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
