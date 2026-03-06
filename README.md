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
- **Anti-XSW protection** -- strict verification mode
- **Zero Python dependencies** -- ships as a single native extension

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
| `verify(ctx, xml)` | Verify a signed XML document |
| `sign(ctx, template)` | Sign an XML template |
| `encrypt(ctx, template, data)` | Encrypt data with an XML template |
| `decrypt(ctx, xml)` | Decrypt an XML document |
| `canonicalize(xml, mode)` | Canonicalize an XML document |
| `digest(uri, data)` | Compute a message digest |
| `validate_cert_chain(...)` | Validate an X.509 certificate chain |
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
