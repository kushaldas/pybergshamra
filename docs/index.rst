pybergshamra documentation
==========================

**pybergshamra** is a Python binding for the `Bergshamra` XML Security library --
a pure-Rust implementation of XML Digital Signatures (XML-DSig), XML Encryption
(XML-Enc), C14N canonicalization, and cryptographic primitives.

Features
--------

- **XML Digital Signatures** -- sign and verify (RSA, EC, Ed25519, HMAC, post-quantum)
- **XML Encryption** -- encrypt and decrypt (AES-CBC/GCM, RSA-OAEP key transport)
- **C14N canonicalization** -- inclusive, exclusive, with/without comments
- **Key management** -- RSA, EC, Ed25519, X25519, HMAC, AES, 3DES, PKCS#12, X.509
- **Certificate validation** -- X.509 chain building and verification with CRL support
- **Cryptographic primitives** -- digest, PBKDF2, HKDF, ConcatKDF
- **Post-quantum signatures** -- ML-DSA-44/65/87, SLH-DSA
- **HSM / PKCS#11** -- sign, verify, encrypt and decrypt with keys held on a hardware token (or SoftHSM2)
- **Anti-XSW protection** -- strict verification mode
- **Zero Python dependencies** -- ships as a single native extension

.. note::

   **Weak-digest X.509 policy.** Starting with Bergshamra 0.5.x, X.509 certificate
   chains signed with weak digests (MD5, SHA-1, SHA-224) are rejected by default.
   pybergshamra is built with Bergshamra's ``legacy-algorithms`` feature enabled, so
   :func:`pybergshamra.validate_cert_chain` (and signature verification that builds an
   X.509 chain) **accepts** these legacy digests for backward compatibility with
   existing certificates and the xmlsec test corpus. There is no per-call runtime
   toggle -- the policy is fixed at build time. If you need strict, secure-by-default
   rejection of weak digests, build the extension yourself with the
   ``legacy-algorithms`` feature removed from the ``bergshamra-keys`` dependency in
   ``Cargo.toml``.

   Note also that PBKDF2 now enforces the RFC 8018 minimum salt length of 8 bytes;
   shorter salts raise :class:`pybergshamra.CryptoError`.

.. toctree::
   :maxdepth: 2
   :caption: Contents

   quickstart
   api
   exceptions
   examples
   migration
