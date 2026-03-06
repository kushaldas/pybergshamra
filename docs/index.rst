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
- **Anti-XSW protection** -- strict verification mode
- **Zero Python dependencies** -- ships as a single native extension

.. toctree::
   :maxdepth: 2
   :caption: Contents

   quickstart
   api
   exceptions
   examples
   migration
