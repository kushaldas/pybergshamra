# pybergshamra

Python bindings for the Bergshamra XML Security library
-- a pure-Rust implementation of XML Digital Signatures (XML-DSig), XML Encryption
(XML-Enc), C14N canonicalization, and cryptographic primitives.

pybergshamra gives you a fast, correct, and memory-safe XML security toolkit from
Python with no C dependencies to compile and no transitive native libraries to audit.

## Features

- **XML Digital Signatures** -- sign and verify (RSA, EC, Ed25519, HMAC, post-quantum)
- **XML Encryption** -- encrypt and decrypt (AES-CBC/GCM, RSA-OAEP key transport)
- **C14N canonicalization** -- inclusive, exclusive, with/without comments
- **Key management** -- RSA, EC, Ed25519, X25519, HMAC, AES, 3DES, PKCS#12, X.509
- **Certificate validation** -- X.509 chain building and verification with CRL support
- **Cryptographic primitives** -- digest, PBKDF2, HKDF, ConcatKDF
- **Post-quantum signatures** -- ML-DSA-44/65/87, SLH-DSA
- **HSM / PKCS#11** -- sign, verify, encrypt and decrypt with keys that never leave a hardware token (or SoftHSM2)
- **Anti-XSW protection** -- strict verification mode
- **Zero Python dependencies** -- ships as a single native extension

## Security note: weak-digest X.509 policy

Starting with Bergshamra 0.5.x, X.509 certificate chains signed with weak digests
(MD5, SHA-1, SHA-224) are **rejected by default**. pybergshamra is built with
Bergshamra's `legacy-algorithms` feature enabled, so `validate_cert_chain()` and
signature verification that builds an X.509 chain **accept** these legacy digests for
backward compatibility with existing certificates. The policy is fixed at build time --
there is no per-call runtime toggle. To get strict, secure-by-default rejection of weak
digests, build the extension yourself with the `legacy-algorithms` feature removed from
the `bergshamra-keys` dependency in `Cargo.toml`.

PBKDF2 also now enforces the RFC 8018 minimum salt length of 8 bytes; shorter salts
raise `CryptoError`.

## Installation

```bash
python3 -m pip install pybergshamra
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv add pybergshamra
```

Wheels are compiled from Rust via [maturin](https://www.maturin.rs/).
Python 3.10+ is required.

## Quick start

### Verify a signed XML document

```python
import pybergshamra

xml = open("signed.xml").read()

manager = pybergshamra.KeysManager()
key = pybergshamra.load_x509_cert_pem(open("cert.pem", "rb").read())
manager.add_key(key)

ctx = pybergshamra.DsigContext(manager)
result = pybergshamra.verify(ctx, xml)

if result:
    print("Valid!", result.key_info.algorithm)
else:
    print("Invalid:", result.reason)
```

### Sign an XML template

```python
import pybergshamra

template = open("sign-template.xml").read()

manager = pybergshamra.KeysManager()
key = pybergshamra.load_rsa_private_pem(open("rsakey.pem", "rb").read())
manager.add_key(key)

ctx = pybergshamra.DsigContext(manager)
signed_xml = pybergshamra.sign(ctx, template)
```

### Encrypt and decrypt

```python
import pybergshamra

# Encrypt
manager = pybergshamra.KeysManager()
key = pybergshamra.load_x509_cert_pem(open("cert.pem", "rb").read())
manager.add_key(key)

ctx = pybergshamra.EncContext(manager)
encrypted_xml = pybergshamra.encrypt(ctx, template_xml, b"secret data")

# Decrypt
manager = pybergshamra.KeysManager()
key = pybergshamra.load_rsa_private_pem(open("rsakey.pem", "rb").read())
manager.add_key(key)

ctx = pybergshamra.EncContext(manager)
decrypted_xml = pybergshamra.decrypt(ctx, encrypted_xml)
```

### Canonicalize XML

```python
import pybergshamra
from pybergshamra import C14nMode

result = pybergshamra.canonicalize(xml_string, C14nMode.Exclusive)
```

### Compute a digest

```python
from pybergshamra import digest, Algorithm

h = digest(Algorithm.SHA256, b"hello world")
print(h.hex())
```

### Sign with a key on an HSM (PKCS#11)

Key material stays on the token; pybergshamra talks to it over PKCS#11 (tested
against SoftHSM2). Algorithms are given as W3C URIs from `Algorithm`; ECDSA also
needs an `ec_curve` because the URI does not encode the curve.

```python
import pybergshamra
from pybergshamra import Algorithm

provider = pybergshamra.Pkcs11Provider("/usr/lib/softhsm/libsofthsm2.so")
session = provider.open_session("1234")  # user PIN

# Sign an XML template with an RSA key on the token
manager = pybergshamra.KeysManager()
sign_ctx = pybergshamra.DsigContext(manager)
sign_ctx.set_hsm_signer(
    pybergshamra.Pkcs11Signer(session, "my-rsa-key", Algorithm.RSA_SHA256)
)
signed_xml = pybergshamra.sign(sign_ctx, template_xml)

# Verify with the matching public key on the token
verify_ctx = pybergshamra.DsigContext(manager)
verify_ctx.set_hsm_verifier(
    pybergshamra.Pkcs11Verifier(session, "my-rsa-key", Algorithm.RSA_SHA256)
)
assert bool(pybergshamra.verify(verify_ctx, signed_xml))
```

`EncContext` exposes the same idea for encryption via `set_hsm_decryptor()`,
`set_hsm_key_unwrapper()`, `set_hsm_encryptor()`, and `set_hsm_key_wrapper()`,
each taking an allow-list of permitted algorithm URIs. The HSM operation classes
(`Pkcs11Signer`, `Pkcs11Verifier`, `Pkcs11Decryptor`, `Pkcs11Encryptor`,
`Pkcs11KeyWrapper`) also expose direct `sign()`/`verify()`/`decrypt()`/
`encrypt()`/`wrap()`/`unwrap()` methods for standalone use.

> Run `bash hsm-test/setup.sh` to provision a local SoftHSM2 token, then
> `SOFTHSM2_CONF=hsm-test/softhsm2.local.conf pytest tests/test_hsm.py` to
> exercise the PKCS#11 path. The CI `hsm` job does the same on every PR.

## API overview

| Class / function | Purpose |
|---|---|
| `Algorithm` | W3C XML Security algorithm URI constants |
| `Key` | A cryptographic key (RSA, EC, HMAC, AES, Ed25519, etc.) |
| `KeyUsage` | Key usage mode (Sign, Verify, Encrypt, Decrypt, Any) |
| `KeysManager()` | Key store for managing keys and certificates |
| `DsigContext(manager)` | Configuration for XML-DSig sign/verify |
| `EncContext(manager)` | Configuration for XML-Enc encrypt/decrypt |
| `C14nMode` | Canonicalization mode (Inclusive, Exclusive, etc.) |
| `VerifyResult` | Result of signature verification |
| `verify(ctx, xml)` | Verify the first `<Signature>` in document order |
| `verify_document(ctx, document)` | Verify a `pyuppsala.Document` without reparsing |
| `verify_all(ctx, xml)` | Verify every `<Signature>` in document order |
| `verify_all_document(ctx, document)` | Verify every signature in a `pyuppsala.Document` |
| `sign(ctx, template)` | Sign an XML template |
| `sign_document(ctx, document)` | Sign a template in a `pyuppsala.Document` in place |
| `sign_enveloped(ctx, xml, ...)` | Build and sign an enveloped `<Signature>` in one step |
| `sign_enveloped_document(ctx, document, ...)` | Build and sign in a `pyuppsala.Document` in place |
| `encrypt(ctx, template, data)` | Encrypt data with an XML template |
| `decrypt(ctx, xml)` | Decrypt an XML document |
| `canonicalize(xml, mode)` | Canonicalize an XML document |
| `digest(uri, data)` | Compute a message digest |
| `validate_cert_chain(...)` | Validate an X.509 certificate chain |
| `parse_pkcs12(data, password)` | Parse a PKCS#12 container into raw keys + certs |
| `Pkcs11Provider` / `Pkcs11Session` | Load a PKCS#11 module and open a token session |
| `Pkcs11Signer` / `Pkcs11Verifier` | HSM-backed XML-DSig signing / verification |
| `Pkcs11Decryptor` / `Pkcs11Encryptor` / `Pkcs11KeyWrapper` | HSM-backed XML-Enc key transport / key wrap |

The native ``*_document`` APIs require pyuppsala 0.9.1 or newer. Install both
packages with ``pip install 'pybergshamra[documents]'``.

`DsigContext(manager)` uses secure defaults (`trusted_keys_only`,
`strict_verification`, `hmac_min_out_len=160`, and required local reference
digests) recommended for federated identity. Use
`DsigContext(manager, secure_defaults=False)` or
`DsigContext.permissive(manager)` only when inline `KeyInfo` and relaxed
structure checks are intentional.
Each `VerifiedReference` now also reports `digest_verified` so callers can tell
whether a reference's digest was actually checked.
| `load_key_file(path)` | Load a key from file (auto-detect format) |
| `load_rsa_private_pem(data)` | Load an RSA private key from PEM |
| `load_x509_cert_pem(data)` | Load an X.509 certificate from PEM |
| `load_hmac_key(data)` | Create an HMAC key from raw bytes |
| `load_aes_key(data)` | Create an AES key from raw bytes |
| `load_pem_auto(data)` | Auto-detect PEM type and load |

See the [full API reference](https://pybergshamra.readthedocs.io/en/latest/api.html)
for all 28 key loaders, algorithm constants, and configuration options.

### Exceptions

| Exception | Raised when |
|---|---|
| `BergshamraError` | Base exception for all errors |
| `XmlError` | XML parsing or structure error |
| `CryptoError` | Cryptographic operation failure |
| `KeyLoadError` | Key loading failure |
| `AlgorithmError` | Unsupported algorithm |
| `EncryptionError` | Encryption/decryption failure |
| `CertificateError` | Certificate validation failure |

All exceptions inherit from `BergshamraError`, which inherits from `Exception`.

## Migrating from python-xmlsec

pybergshamra (together with [pyuppsala](https://pypi.org/project/pyuppsala/) for XML
building) is a complete replacement for python-xmlsec with zero C dependencies. See the
[migration guide](https://pybergshamra.readthedocs.io/en/latest/migration.html) for
side-by-side examples.

## Type stubs

A `pybergshamra.pyi` file is included for full IDE auto-completion and
type-checking with mypy/pyright.

## Development

```bash
# Clone the repository
git clone https://github.com/kushaldas/pybergshamra.git
cd pybergshamra

# Set up the environment with uv
uv sync

# Build the native extension in development mode
uv run maturin develop

# Run the test suite
uv run pytest

# Build a release wheel
uv run maturin build --release
```

## License

BSD-2-Clause
