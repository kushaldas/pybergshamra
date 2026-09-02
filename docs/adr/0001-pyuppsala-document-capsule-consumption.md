# ADR-0001: Exchange pyuppsala Documents as Owned XML

**Date:** 2026-09-02
**Status:** Supersedes the versioned document-capsule design from 2026-07-10

## Context

Pyuppsala and pybergshamra are independently loaded Rust extension modules.
The earlier design placed `Arc<Mutex<OwnedDoc>>` in a versioned `PyCapsule` so
pybergshamra could access pyuppsala's live Uppsala DOM. Matching crate and ABI
versions did not make Rust code pointers or destructors safe across dynamic
library load/unload boundaries. Downstream processes observed segmentation
faults consistent with calling unloaded code.

## Decision

Keep `verify_document`, `verify_all_document`, `sign_document`, and
`sign_enveloped_document`, but cross the extension boundary only with owned XML:

1. Call
   `pyuppsala.Document.to_xml_with_options(include_doctype=True)` while
   attached to Python. The default `to_xml()` omits a preserved DOCTYPE and is
   not a lossless document boundary.
2. Run the existing Bergshamra string API on the resulting owned string.
3. For a successful signing operation, call pyuppsala's internal
   `Document._replace_xml()` hook with the signed string.
4. Pyuppsala parses and imports the replacement into the existing arena. It
   preserves the document element id for live root views and detaches old
   descendant handles rather than letting them alias new nodes.

`pyuppsala-interop`, the capsule, and all unsafe pointer access are removed.
Pybergshamra 0.9.0 requires pyuppsala 0.11.0 for the replacement hook.

## Consequences

- No Rust-owned value, function pointer, or destructor crosses independently
  loaded shared libraries.
- Document verification pays one serialization and one Bergshamra parse.
- Document signing additionally parses and imports the successful result.
- A preserved DOCTYPE crosses the owned-XML boundary and survives signing.
- Signing remains failure-atomic: the caller's pyuppsala document is replaced
  only after Bergshamra returns signed XML successfully.
- Existing Python function names and in-place signing behavior remain intact.
