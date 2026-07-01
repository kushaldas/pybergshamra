"""Type stubs for pybergshamra — Python bindings for the Bergshamra XML Security library."""

from __future__ import annotations

from typing import Optional

# Exceptions

class BergshamraError(Exception): ...
class XmlError(BergshamraError): ...
class CryptoError(BergshamraError): ...
class KeyLoadError(BergshamraError): ...
class AlgorithmError(BergshamraError): ...
class EncryptionError(BergshamraError): ...
class CertificateError(BergshamraError): ...

# Enums

class KeyUsage:
    """Key usage mode."""

    Sign: int
    Verify: int
    Encrypt: int
    Decrypt: int
    Any: int

class C14nMode:
    """XML Canonicalization mode."""

    Inclusive: int
    InclusiveWithComments: int
    Inclusive11: int
    Inclusive11WithComments: int
    Exclusive: int
    ExclusiveWithComments: int

    @property
    def uri(self) -> str:
        """The W3C algorithm URI for this mode."""
        ...
    @property
    def with_comments(self) -> bool:
        """Whether this mode includes comments."""
        ...
    @property
    def is_exclusive(self) -> bool:
        """Whether this mode uses exclusive canonicalization."""
        ...
    @staticmethod
    def from_uri(uri: str) -> Optional[C14nMode]:
        """Look up a C14nMode from its W3C algorithm URI."""
        ...
    def __repr__(self) -> str: ...

# Algorithm constants

class Algorithm:
    """W3C XML Security algorithm URI constants.

    Use these instead of hardcoding URI strings in Python code.
    Example: ``Algorithm.SHA256`` returns the SHA-256 digest URI.
    """

    # Canonicalization (6)
    C14N: str
    C14N_WITH_COMMENTS: str
    C14N11: str
    C14N11_WITH_COMMENTS: str
    EXC_C14N: str
    EXC_C14N_WITH_COMMENTS: str

    # Digest (11)
    SHA1: str
    SHA224: str
    SHA256: str
    SHA384: str
    SHA512: str
    SHA3_224: str
    SHA3_256: str
    SHA3_384: str
    SHA3_512: str
    MD5: str
    RIPEMD160: str

    # RSA Signature (7)
    RSA_SHA1: str
    RSA_SHA224: str
    RSA_SHA256: str
    RSA_SHA384: str
    RSA_SHA512: str
    RSA_MD5: str
    RSA_RIPEMD160: str

    # RSA-PSS Signature (9)
    RSA_PSS_SHA1: str
    RSA_PSS_SHA224: str
    RSA_PSS_SHA256: str
    RSA_PSS_SHA384: str
    RSA_PSS_SHA512: str
    RSA_PSS_SHA3_224: str
    RSA_PSS_SHA3_256: str
    RSA_PSS_SHA3_384: str
    RSA_PSS_SHA3_512: str

    # DSA Signature (2)
    DSA_SHA1: str
    DSA_SHA256: str

    # ECDSA Signature (10)
    ECDSA_SHA1: str
    ECDSA_SHA224: str
    ECDSA_SHA256: str
    ECDSA_SHA384: str
    ECDSA_SHA512: str
    ECDSA_SHA3_224: str
    ECDSA_SHA3_256: str
    ECDSA_SHA3_384: str
    ECDSA_SHA3_512: str
    ECDSA_RIPEMD160: str

    # EdDSA Signature (1)
    EDDSA_ED25519: str

    # HMAC Signature (7)
    HMAC_SHA1: str
    HMAC_SHA224: str
    HMAC_SHA256: str
    HMAC_SHA384: str
    HMAC_SHA512: str
    HMAC_MD5: str
    HMAC_RIPEMD160: str

    # ML-DSA Post-Quantum (3)
    ML_DSA_44: str
    ML_DSA_65: str
    ML_DSA_87: str

    # SLH-DSA Post-Quantum (6)
    SLH_DSA_SHA2_128F: str
    SLH_DSA_SHA2_128S: str
    SLH_DSA_SHA2_192F: str
    SLH_DSA_SHA2_192S: str
    SLH_DSA_SHA2_256F: str
    SLH_DSA_SHA2_256S: str

    # Block Cipher (7)
    AES128_CBC: str
    AES192_CBC: str
    AES256_CBC: str
    AES128_GCM: str
    AES192_GCM: str
    AES256_GCM: str
    TRIPLEDES_CBC: str

    # Key Wrap (4)
    KW_AES128: str
    KW_AES192: str
    KW_AES256: str
    KW_TRIPLEDES: str

    # Key Transport (3)
    RSA_PKCS1: str
    RSA_OAEP: str
    RSA_OAEP_ENC11: str

    # MGF (5)
    MGF1_SHA1: str
    MGF1_SHA224: str
    MGF1_SHA256: str
    MGF1_SHA384: str
    MGF1_SHA512: str

    # Key Agreement (3)
    DH_ES: str
    ECDH_ES: str
    X25519: str

    # Key Derivation (3)
    PBKDF2: str
    CONCAT_KDF: str
    HKDF: str

    # Transform (7)
    BASE64: str
    ENVELOPED_SIGNATURE: str
    XPATH: str
    XPATH2: str
    XSLT: str
    XPOINTER: str
    RELATIONSHIP: str

    # KeyValue Type (5)
    RSA_KEY_VALUE: str
    DSA_KEY_VALUE: str
    EC_KEY_VALUE: str
    DH_KEY_VALUE: str
    DER_ENCODED_KEY_VALUE: str

    # X509 (2)
    X509_DATA: str
    RAW_X509_CERT: str

    # Encrypted/Derived Key (2)
    ENCRYPTED_KEY: str
    DERIVED_KEY: str

# Key classes

class Key:
    """A cryptographic key (RSA, EC, HMAC, AES, Ed25519, X25519, PQ, etc.)."""

    @property
    def name(self) -> Optional[str]:
        """The key name, or None."""
        ...
    @name.setter
    def name(self, value: Optional[str]) -> None: ...
    @property
    def usage(self) -> KeyUsage:
        """The key usage mode."""
        ...
    @usage.setter
    def usage(self, value: KeyUsage) -> None: ...
    @property
    def algorithm_name(self) -> str:
        """The algorithm name (e.g. "RSA", "EC-P256", "HMAC")."""
        ...
    @property
    def has_private_key(self) -> bool:
        """Whether this key contains private key material."""
        ...
    @property
    def x509_chain(self) -> list[bytes]:
        """The DER-encoded X.509 certificate chain, if present."""
        ...
    def to_spki_der(self) -> Optional[bytes]:
        """Return the SPKI DER encoding if available, or None."""
        ...
    def symmetric_key_bytes(self) -> Optional[bytes]:
        """Return the raw symmetric key bytes (HMAC/AES/DES3), or None."""
        ...
    def ec_public_key_bytes(self) -> Optional[bytes]:
        """Return the uncompressed EC public key bytes, or None."""
        ...
    def x25519_public_key_bytes(self) -> Optional[bytes]:
        """Return the X25519 public key bytes (32 bytes), or None."""
        ...
    def x25519_private_key_bytes(self) -> Optional[bytes]:
        """Return the X25519 private key bytes (32 bytes), or None."""
        ...
    def to_key_value_xml(self, prefix: str = "ds") -> Optional[str]:
        """Return the KeyValue XML fragment, or None."""
        ...
    def __repr__(self) -> str: ...

class KeysManager:
    """Key store for managing cryptographic keys and certificates."""

    def __init__(self) -> None: ...
    def add_key(self, key: Key) -> None:
        """Add a key to the manager."""
        ...
    def insert_key_first(self, key: Key) -> None:
        """Insert a key at the front (becomes the first key)."""
        ...
    def first_key(self) -> Optional[Key]:
        """Return the first key, or None."""
        ...
    def keys(self) -> list[Key]:
        """Return all keys as a list."""
        ...
    def find_by_name(self, name: str) -> Optional[Key]:
        """Find a key by name."""
        ...
    def find_by_usage(self, usage: KeyUsage) -> Optional[Key]:
        """Find a key by usage."""
        ...
    def find_rsa(self) -> Optional[Key]:
        """Find the first RSA key."""
        ...
    def find_rsa_private(self) -> Optional[Key]:
        """Find the first RSA key with private material."""
        ...
    def find_hmac(self) -> Optional[Key]:
        """Find the first HMAC key."""
        ...
    def find_aes(self) -> Optional[Key]:
        """Find the first AES key."""
        ...
    def find_aes_by_size(self, size_bytes: int) -> Optional[Key]:
        """Find the first AES key matching the given size in bytes."""
        ...
    def find_des3(self) -> Optional[Key]:
        """Find the first 3DES key."""
        ...
    def find_ec_p256(self) -> Optional[Key]:
        """Find the first EC P-256 key."""
        ...
    def find_ec_p384(self) -> Optional[Key]:
        """Find the first EC P-384 key."""
        ...
    def find_ec_p521(self) -> Optional[Key]:
        """Find the first EC P-521 key."""
        ...
    def find_ed25519(self) -> Optional[Key]:
        """Find the first Ed25519 key."""
        ...
    def find_x25519(self) -> Optional[Key]:
        """Find the first X25519 key."""
        ...
    def find_pq(self) -> Optional[Key]:
        """Find the first post-quantum key."""
        ...
    def find_dh(self) -> Optional[Key]:
        """Find the first DH key."""
        ...
    def add_trusted_cert(self, der: bytes) -> None:
        """Add a trusted DER-encoded X.509 certificate."""
        ...
    def add_untrusted_cert(self, der: bytes) -> None:
        """Add an untrusted DER-encoded X.509 certificate."""
        ...
    def add_crl(self, der: bytes) -> None:
        """Add a DER-encoded CRL."""
        ...
    def trusted_certs(self) -> list[bytes]:
        """Return the trusted certificates as a list of DER bytes."""
        ...
    def untrusted_certs(self) -> list[bytes]:
        """Return the untrusted certificates as a list of DER bytes."""
        ...
    def crls(self) -> list[bytes]:
        """Return the CRLs as a list of DER bytes."""
        ...
    def has_trusted_certs(self) -> bool:
        """Whether the manager has any trusted certificates."""
        ...
    def __len__(self) -> int: ...
    def __bool__(self) -> bool: ...
    def __repr__(self) -> str: ...

# DSig classes

class VerifiedReference:
    """Metadata about a single verified <Reference>."""

    @property
    def uri(self) -> str:
        """The URI attribute from the <Reference> element."""
        ...
    @property
    def resolved_node_id(self) -> Optional[int]:
        """The resolved target node ID (if a same-document reference)."""
        ...
    @property
    def digest_verified(self) -> bool:
        """Whether this reference's digest was cryptographically verified.

        ``False`` for references the engine could not check itself (e.g. ``cid:``
        MIME attachments in WS-Security); verify those out of band.
        """
        ...
    def __repr__(self) -> str: ...

class VerifiedKeyInfo:
    """Information about the key used for verification."""

    @property
    def algorithm(self) -> str:
        """Algorithm name (e.g. "RSA", "EC-P256", "HMAC")."""
        ...
    @property
    def key_name(self) -> Optional[str]:
        """Key name (if resolved by name from KeysManager)."""
        ...
    @property
    def x509_chain(self) -> list[bytes]:
        """DER-encoded X.509 certificate chain (leaf first)."""
        ...
    def __repr__(self) -> str: ...

class VerifyResult:
    """Result of signature verification.

    Use ``bool(result)`` to check signature validity. If your application
    requires every reference digest to be computed locally, also require
    ``all_reference_digests_verified`` or reject ``has_unverified_references``.
    """

    @property
    def is_valid(self) -> bool:
        """Whether the signature is valid."""
        ...
    @property
    def reason(self) -> Optional[str]:
        """The reason for invalidity, or None if valid."""
        ...
    @property
    def references(self) -> Optional[list[VerifiedReference]]:
        """The verified references, or None if invalid."""
        ...
    @property
    def key_info(self) -> Optional[VerifiedKeyInfo]:
        """Information about the verification key, or None if invalid."""
        ...
    @property
    def signature_node_id(self) -> Optional[int]:
        """The node ID of the <Signature> element, or None if invalid."""
        ...
    @property
    def has_unverified_references(self) -> bool:
        """True if valid but at least one <Reference> digest was not computed
        and verified locally (e.g. a ``cid:`` WS-Security MIME attachment).
        Such references must be verified out of band. Always False if invalid.
        """
        ...
    @property
    def all_reference_digests_verified(self) -> bool:
        """True only if valid, with at least one <Reference>, and every
        reference digest was computed and verified locally. False for an
        invalid result or a valid result with no references.
        """
        ...
    def __bool__(self) -> bool: ...
    def __repr__(self) -> str: ...

class DsigContext:
    """Context for XML Digital Signature operations.

    Holds configuration and a KeysManager. Build one, set properties,
    then call ``verify()`` or ``sign()``.
    """

    def __init__(
        self,
        keys_manager: KeysManager,
        *,
        secure_defaults: bool = True,
        trusted_keys_only: Optional[bool] = None,
        strict_verification: Optional[bool] = None,
        hmac_min_out_len: Optional[int] = None,
    ) -> None:
        """Create a DSig context.

        Secure defaults are enabled unless ``secure_defaults=False`` is passed
        as a keyword argument. Individual secure defaults can also be overridden
        with keyword-only arguments.
        """
        ...
    @staticmethod
    def secure(keys_manager: KeysManager) -> DsigContext:
        """Secure-by-default context (mirrors Rust ``DsigContext::new()``):
        ``trusted_keys_only=True``, ``strict_verification=True``,
        ``hmac_min_out_len=160``. Recommended for federated identity / SAML."""
        ...
    @staticmethod
    def permissive(keys_manager: KeysManager) -> DsigContext:
        """Permissive context (mirrors Rust ``DsigContext::new_permissive()``):
        standard W3C behaviour with inline ``KeyInfo`` extraction. Prefer
        ``DsigContext(manager, secure_defaults=False)`` for new code so the
        opt-out is explicit at construction."""
        ...
    def set_hsm_signer(self, signer: Pkcs11Signer) -> None:
        """Use an HSM-backed (PKCS#11) signer for signing."""
        ...
    def set_hsm_verifier(self, verifier: Pkcs11Verifier) -> None:
        """Use an HSM-backed (PKCS#11) verifier for verification."""
        ...
    @property
    def debug(self) -> bool:
        """Debug mode: print pre-digest and pre-signature data to stderr."""
        ...
    @debug.setter
    def debug(self, value: bool) -> None: ...
    @property
    def insecure(self) -> bool:
        """Insecure mode: skip certificate validation."""
        ...
    @insecure.setter
    def insecure(self, value: bool) -> None: ...
    @property
    def verify_keys(self) -> bool:
        """Whether to validate certificates for keys loaded from files."""
        ...
    @verify_keys.setter
    def verify_keys(self, value: bool) -> None: ...
    @property
    def verification_time(self) -> Optional[str]:
        """Verification time override (format: "YYYY-MM-DD+HH:MM:SS")."""
        ...
    @verification_time.setter
    def verification_time(self, value: Optional[str]) -> None: ...
    @property
    def skip_time_checks(self) -> bool:
        """Skip X.509 time checks (NotBefore/NotAfter)."""
        ...
    @skip_time_checks.setter
    def skip_time_checks(self, value: bool) -> None: ...
    @property
    def enabled_key_data_x509(self) -> bool:
        """Whether --enabled-key-data includes x509."""
        ...
    @enabled_key_data_x509.setter
    def enabled_key_data_x509(self, value: bool) -> None: ...
    @property
    def trusted_keys_only(self) -> bool:
        """Only use pre-configured keys, skip inline KeyInfo extraction."""
        ...
    @trusted_keys_only.setter
    def trusted_keys_only(self, value: bool) -> None: ...
    @property
    def strict_verification(self) -> bool:
        """Enforce strict reference target validation (anti-XSW)."""
        ...
    @strict_verification.setter
    def strict_verification(self, value: bool) -> None: ...
    @property
    def hmac_min_out_len(self) -> int:
        """Minimum HMAC output length in bits (0 = spec default)."""
        ...
    @hmac_min_out_len.setter
    def hmac_min_out_len(self, value: int) -> None: ...
    @property
    def base_dir(self) -> Optional[str]:
        """Base directory for resolving relative external URIs."""
        ...
    @base_dir.setter
    def base_dir(self, value: Optional[str]) -> None: ...
    def add_id_attr(self, name: str) -> None:
        """Register an additional ID attribute name."""
        ...
    def add_url_map(self, url: str, file_path: str) -> None:
        """Map a URL to a local file path for external URI resolution."""
        ...

# Enc classes

class EncContext:
    """Context for XML Encryption operations.

    Holds configuration and a KeysManager. Build one, configure it,
    then call ``encrypt()``, ``decrypt()``, or ``decrypt_to_bytes()``.
    """

    def __init__(self, keys_manager: KeysManager) -> None: ...
    @property
    def disable_cipher_reference(self) -> bool:
        """Whether CipherReference resolution is disabled."""
        ...
    @disable_cipher_reference.setter
    def disable_cipher_reference(self, value: bool) -> None: ...
    def add_id_attr(self, name: str) -> None:
        """Register an additional ID attribute name."""
        ...
    def set_hsm_decryptor(
        self, decryptor: Pkcs11Decryptor, allowed_algorithms: list[str]
    ) -> None:
        """Decrypt the wrapped session key via an HSM (PKCS#11) private key.

        ``allowed_algorithms`` is the allow-list of XML-Enc key-transport URIs
        the HSM decryptor may handle (e.g. ``Algorithm.RSA_OAEP``).
        """
        ...
    def set_hsm_key_unwrapper(
        self, unwrapper: Pkcs11KeyWrapper, allowed_algorithms: list[str]
    ) -> None:
        """Unwrap the session key via an HSM (PKCS#11) AES key-wrap key."""
        ...
    def set_hsm_encryptor(
        self, encryptor: Pkcs11Encryptor, allowed_algorithms: list[str]
    ) -> None:
        """Encrypt the session key via an HSM (PKCS#11) public key."""
        ...
    def set_hsm_key_wrapper(
        self, wrapper: Pkcs11KeyWrapper, allowed_algorithms: list[str]
    ) -> None:
        """Wrap the session key via an HSM (PKCS#11) AES key-wrap key."""
        ...

# Module-level functions — DSig

def verify(ctx: DsigContext, xml: str) -> VerifyResult:
    """Verify a signed XML document.

    Returns a VerifyResult. ``bool(result)`` checks signature validity only;
    callers that need full local digest coverage should also require
    ``result.all_reference_digests_verified``.
    """
    ...

def verify_all(ctx: DsigContext, xml: str) -> list[VerifyResult]:
    """Verify every <Signature> element in the document.

    Returns one VerifyResult per signature in document order. Unlike
    ``verify()`` (which reports only the first signature), each signature is
    verified independently and a per-signature failure becomes an invalid entry
    rather than aborting the call, so the list may mix valid and invalid
    results. Use this for multi-signature documents such as SAML responses
    signed at both the Response and Assertion levels.

    Raises only for document-level failures (parse error, duplicate-ID
    conflict, or no ``<Signature>`` element at all).
    """
    ...

def sign(ctx: DsigContext, template_xml: str) -> str:
    """Sign an XML template and return the signed XML string.

    The template must contain a ``<Signature>`` skeleton with
    ``<SignedInfo>``, ``<Reference>``, etc.
    """
    ...

def sign_enveloped(
    ctx: DsigContext,
    xml: str,
    *,
    reference_id: Optional[str] = None,
    signature_method: Optional[str] = None,
    digest_method: Optional[str] = None,
    c14n_method: Optional[str] = None,
    cert_pem: Optional[str] = None,
) -> str:
    """Build an enveloped ``<ds:Signature>`` and sign ``xml`` in one step.

    Constructs a standard enveloped-signature template (SignedInfo with the
    given canonicalization/signature methods; a single Reference to
    ``#{reference_id}`` -- or the whole document when ``reference_id`` is None --
    with enveloped-signature + exclusive-c14n transforms; KeyInfo/X509Data),
    inserts it as the document element's first child, and signs it with the
    context's first key (or HSM signer). Defaults: RSA-SHA256 / SHA-256 /
    exclusive-c14n.

    ``cert_pem`` (one or more PEM CERTIFICATE blocks) is embedded into
    ``X509Data``. Note that ``"ID"`` is already treated as a default ID
    attribute, so do **not** also call :meth:`DsigContext.add_id_attr` with
    ``"ID"`` -- doing so double-registers it and raises a duplicate-ID error.
    """
    ...

# Module-level functions — Enc

def encrypt(ctx: EncContext, template_xml: str, data: bytes) -> str:
    """Encrypt data using an XML template.

    The template must contain an ``<EncryptedData>`` element with an
    empty ``<CipherValue>``. Returns the XML with encrypted content.
    """
    ...

def decrypt(ctx: EncContext, xml: str) -> str:
    """Decrypt an XML document containing ``<EncryptedData>``.

    Returns the decrypted XML as a string.
    """
    ...

def decrypt_to_bytes(ctx: EncContext, xml: str) -> bytes:
    """Decrypt an XML document containing ``<EncryptedData>``.

    Returns the raw decrypted bytes (supports non-UTF-8 content).
    """
    ...

# Module-level functions — C14N

def canonicalize(
    xml: str,
    mode: C14nMode,
    inclusive_prefixes: Optional[list[str]] = None,
) -> bytes:
    """Canonicalize an XML document.

    Args:
        xml: The XML string.
        mode: The C14N mode.
        inclusive_prefixes: Optional list of namespace prefixes to force
            visibly-utilized in exclusive C14N.

    Returns:
        The canonicalized XML as bytes.
    """
    ...

def canonicalize_subtree(
    xml: str,
    element_id: str,
    mode: C14nMode,
    inclusive_prefixes: Optional[list[str]] = None,
) -> bytes:
    """Canonicalize a subtree identified by an element ID.

    Parses the XML, locates the element with the given ID attribute value,
    builds a node set from that subtree, and canonicalizes it.

    Args:
        xml: The XML string.
        element_id: The ID attribute value of the target element.
        mode: The C14N mode.
        inclusive_prefixes: Optional list of namespace prefixes.

    Returns:
        The canonicalized subtree as bytes.
    """
    ...

# Module-level functions — Crypto

def digest(algorithm_uri: str, data: bytes) -> bytes:
    """Compute a one-shot message digest.

    ``algorithm_uri`` is a W3C algorithm URI (e.g. ``Algorithm.SHA256``).
    Returns the digest bytes.
    """
    ...

def pbkdf2_derive(
    password: bytes,
    salt: bytes,
    iteration_count: int,
    key_length: int,
    prf_uri: str,
) -> bytes:
    """Derive a key using PBKDF2 (RFC 8018).

    Args:
        password: The password/secret bytes.
        salt: Salt bytes.
        iteration_count: Number of iterations.
        key_length: Desired output key length in bytes.
        prf_uri: PRF algorithm URI (e.g. ``Algorithm.HMAC_SHA256``).

    Returns the derived key bytes.
    """
    ...

def hkdf_derive(
    shared_secret: bytes,
    key_length: int,
    prf_uri: Optional[str] = None,
    salt: Optional[bytes] = None,
    info: Optional[bytes] = None,
) -> bytes:
    """Derive a key using HKDF (RFC 5869).

    Args:
        shared_secret: Input keying material (IKM).
        key_length: Desired output key length in bytes.
        prf_uri: PRF algorithm URI (default: HMAC-SHA256).
        salt: Optional salt bytes.
        info: Optional context/info bytes.

    Returns the derived key bytes.
    """
    ...

def concat_kdf(
    shared_secret: bytes,
    key_length: int,
    digest_uri: Optional[str] = None,
    algorithm_id: Optional[bytes] = None,
    party_u_info: Optional[bytes] = None,
    party_v_info: Optional[bytes] = None,
) -> bytes:
    """Derive a key using ConcatKDF (NIST SP 800-56A).

    Args:
        shared_secret: The shared secret bytes (Z).
        key_length: Desired output key length in bytes.
        digest_uri: Digest algorithm URI (default: SHA-256).
        algorithm_id: Optional AlgorithmID bytes.
        party_u_info: Optional PartyUInfo bytes.
        party_v_info: Optional PartyVInfo bytes.

    Returns the derived key bytes.
    """
    ...

# Module-level functions — X509

def validate_cert_chain(
    leaf_der: bytes,
    additional_certs: list[bytes] = [],
    trusted_certs: list[bytes] = [],
    untrusted_certs: list[bytes] = [],
    crls: list[bytes] = [],
    verification_time: Optional[str] = None,
    skip_time_checks: bool = False,
) -> None:
    """Validate an X.509 certificate chain.

    Verifies that the leaf certificate chains to a trusted root,
    optionally checking time validity and CRLs.

    Args:
        leaf_der: DER-encoded leaf certificate.
        additional_certs: Extra certificates from XML (DER-encoded).
        trusted_certs: Trusted CA certificates (DER-encoded).
        untrusted_certs: Untrusted intermediate certificates (DER-encoded).
        crls: Certificate Revocation Lists (DER-encoded).
        verification_time: Time override (format: "YYYY-MM-DD+HH:MM:SS").
        skip_time_checks: Skip NotBefore/NotAfter validation.

    Raises ``CertificateError`` on validation failure.
    """
    ...

# Module-level functions — Key loaders

def load_key_file(path: str) -> Key:
    """Load a key from a file (auto-detect format by extension)."""
    ...

def load_key_file_with_password(path: str, password: str) -> Key:
    """Load a key from a password-protected file."""
    ...

def load_pkcs12(data: bytes, password: str) -> Key:
    """Load a key from PKCS#12 data with a password."""
    ...

def load_keys_file(path: str) -> list[Key]:
    """Load keys from an xmlsec keys.xml file."""
    ...

def load_rsa_private_pem(pem_data: bytes) -> Key:
    """Load an RSA private key from PEM data."""
    ...

def load_rsa_public_pem(pem_data: bytes) -> Key:
    """Load an RSA public key from PEM data."""
    ...

def load_ec_p256_private_pem(pem_data: bytes) -> Key:
    """Load an EC P-256 private key from PEM data."""
    ...

def load_ec_p384_private_pem(pem_data: bytes) -> Key:
    """Load an EC P-384 private key from PEM data."""
    ...

def load_ec_p521_private_pem(pem_data: bytes) -> Key:
    """Load an EC P-521 private key from PEM data."""
    ...

def load_x509_cert_pem(pem_data: bytes) -> Key:
    """Load an X.509 certificate from PEM data."""
    ...

def load_x509_cert_der(data: bytes) -> Key:
    """Load an X.509 certificate from DER data."""
    ...

def load_hmac_key(data: bytes) -> Key:
    """Create an HMAC key from raw bytes."""
    ...

def load_aes_key(data: bytes) -> Key:
    """Create an AES key from raw bytes."""
    ...

def load_des3_key(data: bytes) -> Key:
    """Create a 3DES key from raw bytes."""
    ...

def load_pem_auto(pem_data: bytes, password: Optional[str] = None) -> Key:
    """Auto-detect PEM type and load the key."""
    ...

def load_spki_pem(pem_data: bytes) -> Key:
    """Load a public key from SPKI PEM data."""
    ...

def load_spki_der(data: bytes) -> Key:
    """Load a public key from SPKI DER data."""
    ...

def load_ed25519_private_pkcs8_der(data: bytes) -> Key:
    """Load an Ed25519 private key from PKCS#8 DER data."""
    ...

def load_ed25519_public_spki_der(data: bytes) -> Key:
    """Load an Ed25519 public key from SPKI DER data."""
    ...

def load_x25519_private_raw(data: bytes) -> Key:
    """Load an X25519 private key from raw 32-byte data."""
    ...

def load_x25519_public_raw(data: bytes) -> Key:
    """Load an X25519 public key from raw 32-byte data."""
    ...

def parse_keys_xml(xml: str) -> list[Key]:
    """Parse keys from an xmlsec keys.xml string."""
    ...

# Module-level functions — X509 KeyInfo builders

def build_x509_key_info(certs_b64: list[str]) -> str:
    """Build a <KeyInfo><X509Data> XML fragment from base64-encoded certificates."""
    ...

def build_x509_key_info_from_der(certs_der: list[bytes]) -> str:
    """Build a <KeyInfo><X509Data> XML fragment from DER-encoded certificates."""
    ...

# PKCS#12 container parsing

class Pkcs12Contents:
    """The decoded contents of a PKCS#12 (.p12/.pfx) container."""

    @property
    def private_keys(self) -> list[bytes]:
        """PKCS#8 DER-encoded private keys found in the container."""
        ...
    @property
    def certificates(self) -> list[bytes]:
        """DER-encoded X.509 certificates found in the container."""
        ...
    def __repr__(self) -> str: ...

def parse_pkcs12(data: bytes, password: str) -> Pkcs12Contents:
    """Parse a PKCS#12 container into its raw private keys and certificates.

    Unlike :func:`load_pkcs12` (which returns a single ready-to-use :class:`Key`),
    this exposes every private key and certificate in the container.
    """
    ...

# HSM / PKCS#11 support
#
# Drive XML-DSig signing/verification and XML-Enc encryption/decryption with key
# material that never leaves a hardware token (or SoftHSM2). Algorithms are
# given as W3C URIs (use the ``Algorithm`` constants); ECDSA additionally needs
# ``ec_curve`` because the URI does not encode the curve.

class Pkcs11Provider:
    """A loaded PKCS#11 module bound to the first slot with a token present."""

    def __init__(self, library_path: str) -> None: ...
    def open_session(self, pin: str) -> Pkcs11Session:
        """Open an authenticated read/write session using a UTF-8 user PIN."""
        ...
    def open_session_bytes(self, pin: bytes) -> Pkcs11Session:
        """Open an authenticated read/write session using a raw-byte PIN."""
        ...
    def __repr__(self) -> str: ...

class Pkcs11Session:
    """An authenticated PKCS#11 session. Pass it to the operation constructors."""

    def __repr__(self) -> str: ...

class Pkcs11Signer:
    """Produces signatures using a private (or HMAC secret) key on the token."""

    def __init__(
        self,
        session: Pkcs11Session,
        key_label: str,
        algorithm: str,
        ec_curve: Optional[str] = None,
    ) -> None: ...
    def sign(self, data: bytes) -> bytes:
        """Sign ``data`` directly (mostly for testing); returns the raw signature."""
        ...
    def __repr__(self) -> str: ...

class Pkcs11Verifier:
    """Verifies signatures using a public (or HMAC secret) key on the token."""

    def __init__(
        self,
        session: Pkcs11Session,
        key_label: str,
        algorithm: str,
        ec_curve: Optional[str] = None,
    ) -> None: ...
    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify ``signature`` over ``data`` directly (mostly for testing)."""
        ...
    def __repr__(self) -> str: ...

class Pkcs11Decryptor:
    """Decrypts a wrapped key (RSA-OAEP / RSA-PKCS1) using a private key on the token."""

    def __init__(
        self,
        session: Pkcs11Session,
        key_label: str,
        algorithm: str,
        digest: Optional[str] = None,
        mgf: Optional[str] = None,
        oaep_label: Optional[bytes] = None,
    ) -> None: ...
    def decrypt(self, ciphertext: bytes) -> bytes: ...
    def __repr__(self) -> str: ...

class Pkcs11Encryptor:
    """Encrypts a key (RSA-OAEP / RSA-PKCS1) using a public key on the token."""

    def __init__(
        self,
        session: Pkcs11Session,
        key_label: str,
        algorithm: str,
        digest: Optional[str] = None,
        mgf: Optional[str] = None,
        oaep_label: Optional[bytes] = None,
    ) -> None: ...
    def encrypt(self, plaintext: bytes) -> bytes: ...
    def __repr__(self) -> str: ...

class Pkcs11KeyWrapper:
    """Wraps/unwraps symmetric keys with an AES KEK on the token (RFC 3394)."""

    def __init__(
        self, session: Pkcs11Session, key_label: str, algorithm: str
    ) -> None: ...
    def wrap(self, key_data: bytes) -> bytes: ...
    def unwrap(self, wrapped: bytes) -> bytes: ...
    def __repr__(self) -> str: ...
