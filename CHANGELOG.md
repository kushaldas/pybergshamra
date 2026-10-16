# Changelog

## 0.10.0 [2026-10-16]

### Changed

- Update all Bergshamra crates to 0.10.1 from crates.io, removing the local
  path overrides used while the performance work was in progress. Bergshamra
  0.10.x brings the incremental inclusive C14N serializer, arena-borrowed
  attribute rendering, pre-sized output buffers, and Uppsala 0.12.0.
- All hot entry points (`verify`, `verify_all`, `sign`, `sign_enveloped`,
  `canonicalize`, `canonicalize_subtree`, `encrypt`, `decrypt`,
  `decrypt_to_bytes`) now release the GIL for their CPU-bound Rust work, so
  multi-threaded Python callers scale across cores (4-thread verify wall time
  dropped ~57%). Arguments passed as `str` or `bytes` are copied before the
  GIL is released.
- The extension is built with fat LTO, a single codegen unit, and stripped
  symbols.
- Added `benchmarks/pybench.py` for reproducible Python-layer A/B measurement
  (`docs/performance/20261007-optimized-crates-gil-release.md` has results and
  methodology). With `--json` the timing rows go to stderr so stdout carries
  exactly one JSON document.
- Bergshamra 0.10.x accepts the W3C `http://www.w3.org/2026/08/xmldsig-more`
  identifiers for ML-DSA-44/65/87 and for SLH-DSA SHA2-128s/128f/192s/192f/
  256s/256f alongside the xmlsec ones, so metadata feeds signed with the W3C
  post-quantum namespace, such as the eduID Luxembourg ML-DSA-87 and
  SLH-DSA-SHA2-256s upstream feeds, verify through `verify`,
  `verify_document`, and the pyFF loader. Injected PKCS#11 signers and
  verifiers match either spelling of the same parameter set.
  `Algorithm.ML_DSA_*_W3C` and `Algorithm.SLH_DSA_SHA2_*_W3C` expose the W3C
  identifiers next to the existing xmlsec constants. The SLH-DSA SHAKE
  parameter sets are not implemented.
- Require `uppsala` 0.12.0 on the Rust side and `pyuppsala` 0.13.0 or newer
  for the `*_document` APIs and the test suite; pyuppsala is now a hard test
  dependency pinned to 0.13.0 in the development lockfile, so the document
  tests no longer skip when it is absent and always exercise the
  fragment-splice path below.
- `sign_enveloped_document` now hands pyuppsala only the computed
  `<ds:Signature>` fragment (through a callable
  `Document._prepend_fragment_xml`, pyuppsala 0.13+) instead of replacing the
  whole document with re-parsed owned XML, and all `*_document` APIs read the
  document as `bytes` when `Document.to_xml_bytes_with_options` exists. On a
  108 MB eduGAIN aggregate this removes one full serialization and one full
  reparse per signature. Documents without a callable fragment hook keep the
  owned-XML replacement path; both hooks are resolved before any (possibly
  HSM-backed) signature is produced.
- `sign_document` and `sign_enveloped_document` hold the target
  `pyuppsala.Document` for the whole snapshot, sign, and update sequence, so
  concurrent pybergshamra calls on the same document are serialized (waiting
  with the GIL released) and every later signature covers the earlier ones.
  Verification of a document covers the snapshot taken at call time.
  Mutating a document through pyuppsala, including element proxies, while a
  signing call on it is in progress is the caller's responsibility; the API
  reference documents these rules.

## 0.9.2 [2026-09-28]

### Changed

- Update all Bergshamra crates to 0.9.2 and Kryptering to 0.6.0 from
  crates.io, including tsp-ltv 0.5.0 for certificate validation.
- PKCS#11 session creation now rejects an existing token login. Reuse an
  authenticated session across operations, or close all sessions and operation
  objects before logging in again.
- Refresh the Rust and Python lockfiles and documentation release version.

## 0.9.1 [2026-09-23]

### Security

- Updated `cryptoki` 0.12.0 -> 0.12.1 to address RUSTSEC-2026-0286.

### Changed

- Document signing now parses the owned XML handoff once and uses Bergshamra's
  native in-place Uppsala signer. This preserves the safe serialized boundary
  with pyuppsala while avoiding redundant full-document parses for large XML
  aggregates.
- Updated all `bergshamra` crates 0.9.0 -> 0.9.1, including the batched
  reference-digest and incremental exclusive-C14N performance improvements.

## 0.9.0 [2026-09-02]

### Security

- Removed direct access to Rust-owned pyuppsala DOM data through a cross-shared-
  library capsule. The capsule could outlive the extension code that created
  its Rust values and caused downstream segmentation faults.

### Changed

- Updated all `bergshamra` crates 0.8.0 -> 0.9.0 and Uppsala to 0.10.1.
- Removed the `pyuppsala-interop` dependency. The `*_document()` APIs retain
  their Python signatures but now exchange owned XML strings: verification
  serializes and reparses, while successful signing reparses and safely imports
  the replacement tree into the existing pyuppsala document arena.
- Document APIs now require pyuppsala 0.11.0 or newer.
- Document APIs use DOCTYPE-inclusive serialization so signing does not discard
  preserved document metadata.


## 0.8.1 [2026-09-01]

### Added

- Added ``Pkcs11Provider.with_token()`` for selecting a unique initialized
  PKCS#11 token by label and optional serial number in multi-token deployments.
- Added ``Pkcs11Provider.with_slot_id()`` for selecting a specific initialized
  PKCS#11 slot and the read-only ``Pkcs11Provider.slot_id`` property for
  inspecting the selected slot.
- Expanded the SoftHSM2 integration setup to provision two initialized tokens
  and test fail-closed default selection, token-label/serial selection, and
  explicit slot-ID selection.


## 0.8.0 [2026-08-02]

### Changed

- Updated all `bergshamra` crates `0.7.1` -> `0.8.0` and `kryptering`
  `0.4.1` -> `0.5.0`. Document cryptography now goes through Kryptering's
  selectable provider layer; this build keeps the RustCrypto-based defaults
  (`rustcrypto`, `legacy-algorithms`, `post-quantum`, `pkcs11`).
- MSRV raised to Rust 1.88 (bergshamra 0.8.0 requirement).
- `load_hmac_key()` can now raise `KeyLoadError` if the selected crypto
  provider rejects the key import (previously it could not fail).
- `Key.x25519_public_key_bytes()` / `Key.x25519_private_key_bytes()` are now
  exported through the provider key handle and can raise `KeyLoadError` on
  provider export failure; the returned raw 32-byte values are unchanged.
- Updated `pyuppsala-interop` `0.1.0` -> `0.2.0` for pyuppsala 0.10.0's
  zero-copy document capsule (ABI v2). The document-native functions
  (`verify_document()`, `sign_document()`, `sign_enveloped_document()`, ...)
  now require documents from pyuppsala >= 0.10.0; v1 capsules from older
  pyuppsala builds are rejected with a clear ABI error. Signing works
  in place on zero-copy documents with no extra conversion.

### Added

- Added ``verify_document()``, ``verify_all_document()``, ``sign_document()``,
  and ``sign_enveloped_document()`` for operating directly on a
  ``pyuppsala.Document`` through its native document capsule.

### Changed

- Native document signing and verification release the Python GIL and avoid
  serializing and reparsing the caller's Uppsala DOM on common same-document
  XML-DSig paths.


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
