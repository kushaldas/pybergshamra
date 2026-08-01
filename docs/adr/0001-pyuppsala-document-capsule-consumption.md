# ADR-0001: Consume pyuppsala Documents Through the Versioned Document Capsule

**Date:** 2026-07-10
**Status:** Accepted
**Context:** Signing and verifying pyuppsala documents without serializing them to strings and re-parsing them inside bergshamra

## Problem

pybergshamra's original API is string-in/string-out: `sign_enveloped(ctx,
xml)` returns signed XML text, `verify(ctx, xml)` parses its input. A caller
like pyFF that already holds a pyuppsala DOM pays a full serialization before
every call, whole-document parses inside bergshamra, and a re-parse of the
returned text, four or more document-sized XML passes per signature on a
100 MB metadata aggregate.

pyuppsala and pybergshamra are sibling Rust extensions built on the same
`uppsala` DOM, so a zero-copy handoff is possible if both sides can name the
same ownership type.

## Decision

Consume pyuppsala's document handle capsule (pyuppsala ADR 0002) and add
document-native module functions that mirror the string API:
`sign_document`, `sign_enveloped_document`, `verify_document`, and
`verify_all_document`, each taking a `pyuppsala.Document`.

Mechanics of `shared_document()` (src/dsig.rs):

1. Call the document's `_bergshamra_document_capsule()` and cast to
   `PyCapsule`.
2. Request the capsule pointer by its exact versioned name
   (`pyuppsala.document_handle.v2`); a name mismatch fails immediately.
3. Check the payload's ABI number against `DOCUMENT_CAPSULE_ABI` from
   `pyuppsala-interop` before reading anything else; a mismatch raises a
   `TypeError` instead of misinterpreting memory.
4. Clone the `Arc<Mutex<OwnedDoc>>` out of the payload and drop the capsule.
   The cloned Arc keeps the document alive for the whole native operation.

Each function then runs under `py.detach(..)` (GIL released) and takes the
document mutex inside the detached closure, matching pyuppsala's lock order
(GIL before document mutex). Mutation goes through the interop crate's
`with_doc_mut` closure accessor, the only sanctioned way to obtain
`&mut Document`. Owned copies of all `&str` arguments are made before
detaching because they may borrow Python string storage.

Version policy: pybergshamra pins `pyuppsala-interop` by exact version and
must be released in lock step with pyuppsala whenever the capsule ABI moves
(v1 to v2 happened when pyuppsala adopted zero-copy documents). The string API
remains for callers without pyuppsala trees, and callers such as pyFF feature-
detect with `hasattr(pybergshamra, "sign_enveloped_document")` and fall back
to strings.

## Consequences

- Signing operates in place on the shared DOM: pyFF's sign pipe passes
  `etree.native_document(root)` and keeps the very same tree afterward, with
  the `<ds:Signature>` inserted; no document-sized strings cross the boundary
  in either direction.
- Rust-layer effect (bergshamra ADR 0008 benchmark): sign 20 MB 1.88 s to
  717 ms; end-to-end, pyFF's eduGAIN build dropped about 25 percent wall and
  19 percent peak RSS in the cycle that wired this in.
- The GIL is released during sign/verify, so other Python threads make
  progress during the C14N and RSA work.
- Non-pyuppsala objects raise `TypeError` (covered by
  `test_document_api_rejects_non_pyuppsala_object`), and a
  pyuppsala/pybergshamra version mismatch fails loudly at the capsule check
  rather than corrupting memory.
