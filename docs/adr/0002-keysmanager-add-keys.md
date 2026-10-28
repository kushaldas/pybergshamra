# ADR-0002: `KeysManager.add_keys` for Trusted Key Sets

**Date:** 2026-10-28
**Status:** Accepted
**Context:** Certificate rollover in signed metadata (eIDAS, SAML federations)
verified through pybergshamra, for example by pyFF.

## Context

A metadata publisher that rolls its signing certificate signs with the old
certificate until a switch date and with the new one afterwards. The verifier
must accept both during the overlap. pyFF did this before by verifying once
per certificate with a separate `DsigContext` each time.

Bergshamra 0.11.1 (ADR-0013) changes `trusted_keys_only` verification to
try every compatible key in the `KeysManager` and accept the signature when
any of them verifies it. That ADR holds the security analysis:
document-supplied keys are never candidates, each key passes its own X.509
policy, and every manager entry is an accepted signer. The bindings get that
behavior with no API change: calling `add_key` once per certificate is
enough.

What remains is how Python callers load several keys. A proposal from pyFF
suggested either a loop over `add_key` or passing a list to `add_key`.

## Decision

1. Keep `add_key(key)` taking exactly one `Key`.
2. Add `add_keys(keys)`, accepting any iterable of `Key` (list, tuple,
   generator), and adding them in iteration order.
3. `add_keys` is all-or-nothing: it consumes the iterable and type-checks
   every item before taking the manager lock. A non-`Key` item raises
   `TypeError` naming the offending type, and the manager is unchanged.
   Exceptions raised by the iterable itself propagate the same way.
4. Each key is copied into the manager, as with `add_key`; later changes to
   the Python `Key` (for example `key.name`) do not affect the stored copy.
5. The binding validates and copies every item, then hands the batch to the
   Rust `KeysManager::add_keys` under one lock. Both `add_keys` and
   multi-key verification require Bergshamra 0.11.1, the minimum version
   since pybergshamra 0.11.1.

## Alternatives Considered

### Make `add_key` accept a `Key` or a list

Rejected. A union parameter makes the stub type `Key | Iterable[Key]`,
hides the bulk case in a single-item name, and gives worse errors when
something else is passed. The Rust API uses the same two-method split.

### Partial insertion on error

Rejected. If the fifth certificate of a list fails the type check, a manager
holding the first four is a configuration the caller did not ask for, and a
retry would duplicate them. Validating first costs one extra `Vec`.

### No new method

Viable, since a loop over `add_key` works. Rejected because pyFF and similar
callers load a list of certificates from configuration, and a single call
reads better and documents the trust-set semantics in one place.

## Consequences

- `manager.add_keys(load_x509_cert_pem(p) for p in pems)` is the
  recommended way to load a rollover set.
- Documentation states that one manager is one trust set; signers that must
  not vouch for each other need separate managers.
- `tests/test_pybergshamra.py` covers ordering, iterables, the all-or-nothing
  type check, and rollover verification with two certificates in either
  order (`TestTrustedKeySet`). Against Bergshamra 0.11.0 the rollover cases
  where the signer is not loaded first, and the check of the multi-key
  failure reason, fail; with 0.11.1 all pass.
