API reference
=============

Algorithm constants
-------------------

.. class:: Algorithm

   Static class containing W3C XML Security algorithm URI strings. Use these
   instead of hardcoding URI strings in your code.

   .. code-block:: python

      from pybergshamra import Algorithm

      print(Algorithm.RSA_SHA256)
      # "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

   **Canonicalization**

   .. attribute:: C14N
      :type: str

      Inclusive C14N (``http://www.w3.org/TR/2001/REC-xml-c14n-20010315``)

   .. attribute:: C14N_WITH_COMMENTS
      :type: str

      Inclusive C14N with comments

   .. attribute:: C14N11
      :type: str

      Inclusive C14N 1.1 (``http://www.w3.org/2006/12/xml-c14n11``)

   .. attribute:: C14N11_WITH_COMMENTS
      :type: str

      Inclusive C14N 1.1 with comments

   .. attribute:: EXC_C14N
      :type: str

      Exclusive C14N (``http://www.w3.org/2001/10/xml-exc-c14n#``)

   .. attribute:: EXC_C14N_WITH_COMMENTS
      :type: str

      Exclusive C14N with comments

   **Digest**

   .. attribute:: SHA1
      :type: str

      SHA-1 digest

   .. attribute:: SHA224
      :type: str

      SHA-224 digest

   .. attribute:: SHA256
      :type: str

      SHA-256 digest

   .. attribute:: SHA384
      :type: str

      SHA-384 digest

   .. attribute:: SHA512
      :type: str

      SHA-512 digest

   .. attribute:: SHA3_224
      :type: str

      SHA3-224 digest

   .. attribute:: SHA3_256
      :type: str

      SHA3-256 digest

   .. attribute:: SHA3_384
      :type: str

      SHA3-384 digest

   .. attribute:: SHA3_512
      :type: str

      SHA3-512 digest

   .. attribute:: MD5
      :type: str

      MD5 digest (legacy, not recommended)

   .. attribute:: RIPEMD160
      :type: str

      RIPEMD-160 digest (legacy)

   **RSA Signature**

   .. attribute:: RSA_SHA1
      :type: str

      RSA with SHA-1

   .. attribute:: RSA_SHA224
      :type: str

      RSA with SHA-224

   .. attribute:: RSA_SHA256
      :type: str

      RSA with SHA-256

   .. attribute:: RSA_SHA384
      :type: str

      RSA with SHA-384

   .. attribute:: RSA_SHA512
      :type: str

      RSA with SHA-512

   .. attribute:: RSA_MD5
      :type: str

      RSA with MD5 (legacy, not recommended)

   .. attribute:: RSA_RIPEMD160
      :type: str

      RSA with RIPEMD-160 (legacy)

   **RSA-PSS Signature**

   .. attribute:: RSA_PSS_SHA1
      :type: str

      RSA-PSS with SHA-1

   .. attribute:: RSA_PSS_SHA224
      :type: str

      RSA-PSS with SHA-224

   .. attribute:: RSA_PSS_SHA256
      :type: str

      RSA-PSS with SHA-256

   .. attribute:: RSA_PSS_SHA384
      :type: str

      RSA-PSS with SHA-384

   .. attribute:: RSA_PSS_SHA512
      :type: str

      RSA-PSS with SHA-512

   .. attribute:: RSA_PSS_SHA3_224
      :type: str

      RSA-PSS with SHA3-224

   .. attribute:: RSA_PSS_SHA3_256
      :type: str

      RSA-PSS with SHA3-256

   .. attribute:: RSA_PSS_SHA3_384
      :type: str

      RSA-PSS with SHA3-384

   .. attribute:: RSA_PSS_SHA3_512
      :type: str

      RSA-PSS with SHA3-512

   **DSA Signature**

   .. attribute:: DSA_SHA1
      :type: str

      DSA with SHA-1

   .. attribute:: DSA_SHA256
      :type: str

      DSA with SHA-256

   **ECDSA Signature**

   .. attribute:: ECDSA_SHA1
      :type: str

      ECDSA with SHA-1

   .. attribute:: ECDSA_SHA224
      :type: str

      ECDSA with SHA-224

   .. attribute:: ECDSA_SHA256
      :type: str

      ECDSA with SHA-256

   .. attribute:: ECDSA_SHA384
      :type: str

      ECDSA with SHA-384

   .. attribute:: ECDSA_SHA512
      :type: str

      ECDSA with SHA-512

   .. attribute:: ECDSA_SHA3_224
      :type: str

      ECDSA with SHA3-224

   .. attribute:: ECDSA_SHA3_256
      :type: str

      ECDSA with SHA3-256

   .. attribute:: ECDSA_SHA3_384
      :type: str

      ECDSA with SHA3-384

   .. attribute:: ECDSA_SHA3_512
      :type: str

      ECDSA with SHA3-512

   .. attribute:: ECDSA_RIPEMD160
      :type: str

      ECDSA with RIPEMD-160 (legacy)

   **EdDSA Signature**

   .. attribute:: EDDSA_ED25519
      :type: str

      Ed25519 signature

   **HMAC Signature**

   .. attribute:: HMAC_SHA1
      :type: str

      HMAC with SHA-1

   .. attribute:: HMAC_SHA224
      :type: str

      HMAC with SHA-224

   .. attribute:: HMAC_SHA256
      :type: str

      HMAC with SHA-256

   .. attribute:: HMAC_SHA384
      :type: str

      HMAC with SHA-384

   .. attribute:: HMAC_SHA512
      :type: str

      HMAC with SHA-512

   .. attribute:: HMAC_MD5
      :type: str

      HMAC with MD5 (legacy, not recommended)

   .. attribute:: HMAC_RIPEMD160
      :type: str

      HMAC with RIPEMD-160 (legacy)

   **ML-DSA Post-Quantum**

   .. attribute:: ML_DSA_44
      :type: str

      ML-DSA-44 (FIPS 204)

   .. attribute:: ML_DSA_65
      :type: str

      ML-DSA-65 (FIPS 204)

   .. attribute:: ML_DSA_87
      :type: str

      ML-DSA-87 (FIPS 204)

   **SLH-DSA Post-Quantum**

   .. attribute:: SLH_DSA_SHA2_128F
      :type: str

      SLH-DSA-SHA2-128f (FIPS 205)

   .. attribute:: SLH_DSA_SHA2_128S
      :type: str

      SLH-DSA-SHA2-128s (FIPS 205)

   .. attribute:: SLH_DSA_SHA2_192F
      :type: str

      SLH-DSA-SHA2-192f (FIPS 205)

   .. attribute:: SLH_DSA_SHA2_192S
      :type: str

      SLH-DSA-SHA2-192s (FIPS 205)

   .. attribute:: SLH_DSA_SHA2_256F
      :type: str

      SLH-DSA-SHA2-256f (FIPS 205)

   .. attribute:: SLH_DSA_SHA2_256S
      :type: str

      SLH-DSA-SHA2-256s (FIPS 205)

   **Block Cipher**

   .. attribute:: AES128_CBC
      :type: str

      AES-128 in CBC mode

   .. attribute:: AES192_CBC
      :type: str

      AES-192 in CBC mode

   .. attribute:: AES256_CBC
      :type: str

      AES-256 in CBC mode

   .. attribute:: AES128_GCM
      :type: str

      AES-128 in GCM mode

   .. attribute:: AES192_GCM
      :type: str

      AES-192 in GCM mode

   .. attribute:: AES256_GCM
      :type: str

      AES-256 in GCM mode

   .. attribute:: TRIPLEDES_CBC
      :type: str

      Triple DES in CBC mode (legacy)

   **Key Wrap**

   .. attribute:: KW_AES128
      :type: str

      AES-128 key wrap

   .. attribute:: KW_AES192
      :type: str

      AES-192 key wrap

   .. attribute:: KW_AES256
      :type: str

      AES-256 key wrap

   .. attribute:: KW_TRIPLEDES
      :type: str

      Triple DES key wrap (legacy)

   **Key Transport**

   .. attribute:: RSA_PKCS1
      :type: str

      RSA PKCS#1 v1.5 key transport (legacy)

   .. attribute:: RSA_OAEP
      :type: str

      RSA-OAEP key transport

   .. attribute:: RSA_OAEP_ENC11
      :type: str

      RSA-OAEP (XML Encryption 1.1)

   **Mask Generation Function (MGF)**

   .. attribute:: MGF1_SHA1
      :type: str

      MGF1 with SHA-1

   .. attribute:: MGF1_SHA224
      :type: str

      MGF1 with SHA-224

   .. attribute:: MGF1_SHA256
      :type: str

      MGF1 with SHA-256

   .. attribute:: MGF1_SHA384
      :type: str

      MGF1 with SHA-384

   .. attribute:: MGF1_SHA512
      :type: str

      MGF1 with SHA-512

   **Key Agreement**

   .. attribute:: DH_ES
      :type: str

      Diffie-Hellman ephemeral-static

   .. attribute:: ECDH_ES
      :type: str

      ECDH ephemeral-static

   .. attribute:: X25519
      :type: str

      X25519 key agreement

   **Key Derivation**

   .. attribute:: PBKDF2
      :type: str

      PBKDF2 key derivation

   .. attribute:: CONCAT_KDF
      :type: str

      ConcatKDF key derivation

   .. attribute:: HKDF
      :type: str

      HKDF key derivation

   **Transform**

   .. attribute:: BASE64
      :type: str

      Base64 transform

   .. attribute:: ENVELOPED_SIGNATURE
      :type: str

      Enveloped signature transform

   .. attribute:: XPATH
      :type: str

      XPath transform

   .. attribute:: XPATH2
      :type: str

      XPath 2.0 filter transform

   .. attribute:: XSLT
      :type: str

      XSLT transform

   .. attribute:: XPOINTER
      :type: str

      XPointer transform

   .. attribute:: RELATIONSHIP
      :type: str

      Relationship transform

   **KeyValue Type**

   .. attribute:: RSA_KEY_VALUE
      :type: str

      RSA KeyValue

   .. attribute:: DSA_KEY_VALUE
      :type: str

      DSA KeyValue

   .. attribute:: EC_KEY_VALUE
      :type: str

      EC KeyValue

   .. attribute:: DH_KEY_VALUE
      :type: str

      DH KeyValue

   .. attribute:: DER_ENCODED_KEY_VALUE
      :type: str

      DER-encoded KeyValue

   **X509**

   .. attribute:: X509_DATA
      :type: str

      X509Data key data

   .. attribute:: RAW_X509_CERT
      :type: str

      Raw X.509 certificate

   **Encrypted/Derived Key**

   .. attribute:: ENCRYPTED_KEY
      :type: str

      EncryptedKey

   .. attribute:: DERIVED_KEY
      :type: str

      DerivedKey

Key management
--------------

KeyUsage
^^^^^^^^

.. class:: KeyUsage

   Key usage mode enumeration. Pass these values to :meth:`Key.usage` or
   :meth:`KeysManager.find_by_usage`.

   .. attribute:: Sign

      Key is used for signing.

   .. attribute:: Verify

      Key is used for signature verification.

   .. attribute:: Encrypt

      Key is used for encryption.

   .. attribute:: Decrypt

      Key is used for decryption.

   .. attribute:: Any

      Key can be used for any purpose (default).

   .. code-block:: python

      import pybergshamra
      from pybergshamra import KeyUsage

      key = pybergshamra.load_rsa_private_pem(pem_data)
      key.usage = KeyUsage.Sign

      manager = pybergshamra.KeysManager()
      manager.add_key(key)
      found = manager.find_by_usage(KeyUsage.Sign)

Key
^^^

.. class:: Key

   A cryptographic key (RSA, EC, HMAC, AES, Ed25519, X25519, PQ, etc.).
   Keys are created through the key loader functions, not constructed directly.

   .. attribute:: name
      :type: str | None

      The key name, or ``None``. Readable and writable.

      .. code-block:: python

         key = pybergshamra.load_rsa_private_pem(pem_data)
         key.name = "my-signing-key"
         print(key.name)  # "my-signing-key"

   .. attribute:: usage
      :type: KeyUsage

      The key usage mode. Readable and writable.

   .. attribute:: algorithm_name
      :type: str

      The algorithm name (read-only). Examples: ``"RSA"``, ``"EC-P256"``,
      ``"HMAC"``, ``"AES"``, ``"3DES"``, ``"Ed25519"``, ``"X25519"``.

      .. code-block:: python

         key = pybergshamra.load_rsa_private_pem(pem_data)
         print(key.algorithm_name)  # "RSA"

   .. attribute:: has_private_key
      :type: bool

      Whether this key contains private key material (read-only).

   .. attribute:: x509_chain
      :type: list[bytes]

      The DER-encoded X.509 certificate chain, if present (read-only).

   .. method:: to_spki_der() -> bytes | None

      Return the SPKI DER encoding of the public key, or ``None`` if not
      available.

   .. method:: symmetric_key_bytes() -> bytes | None

      Return the raw symmetric key bytes (HMAC/AES/DES3), or ``None``.

   .. method:: ec_public_key_bytes() -> bytes | None

      Return the uncompressed EC public key bytes, or ``None``.

   .. method:: x25519_public_key_bytes() -> bytes | None

      Return the X25519 public key bytes (32 bytes), or ``None``.

   .. method:: x25519_private_key_bytes() -> bytes | None

      Return the X25519 private key bytes (32 bytes), or ``None``.

   .. method:: to_key_value_xml(prefix: str = "ds") -> str | None

      Return the KeyValue XML fragment, or ``None``. The returned XML uses
      the given namespace prefix.

      .. code-block:: python

         key = pybergshamra.load_rsa_private_pem(pem_data)
         xml_fragment = key.to_key_value_xml()
         # Returns e.g. "<ds:RSAKeyValue>...</ds:RSAKeyValue>"

KeysManager
^^^^^^^^^^^

.. class:: KeysManager()

   Key store for managing cryptographic keys and certificates.

   .. code-block:: python

      import pybergshamra

      manager = pybergshamra.KeysManager()
      key = pybergshamra.load_rsa_private_pem(pem_data)
      manager.add_key(key)

      print(len(manager))  # 1
      print(bool(manager))  # True

   .. method:: add_key(key: Key) -> None

      Add a key to the manager.

   .. method:: insert_key_first(key: Key) -> None

      Insert a key at the front (becomes the first key).

   .. method:: first_key() -> Key | None

      Return the first key, or ``None`` if the manager is empty.

   .. method:: keys() -> list[Key]

      Return all keys as a list.

   .. method:: find_by_name(name: str) -> Key | None

      Find a key by name.

      .. code-block:: python

         key = pybergshamra.load_hmac_key(b"secret")
         key.name = "my-hmac"
         manager.add_key(key)
         found = manager.find_by_name("my-hmac")

   .. method:: find_by_usage(usage: KeyUsage) -> Key | None

      Find a key by usage mode.

   .. method:: find_rsa() -> Key | None

      Find the first RSA key.

   .. method:: find_rsa_private() -> Key | None

      Find the first RSA key with private material.

   .. method:: find_hmac() -> Key | None

      Find the first HMAC key.

   .. method:: find_aes() -> Key | None

      Find the first AES key.

   .. method:: find_aes_by_size(size_bytes: int) -> Key | None

      Find the first AES key matching the given size in bytes (16, 24, or 32).

   .. method:: find_des3() -> Key | None

      Find the first 3DES key.

   .. method:: find_ec_p256() -> Key | None

      Find the first EC P-256 key.

   .. method:: find_ec_p384() -> Key | None

      Find the first EC P-384 key.

   .. method:: find_ec_p521() -> Key | None

      Find the first EC P-521 key.

   .. method:: find_ed25519() -> Key | None

      Find the first Ed25519 key.

   .. method:: find_x25519() -> Key | None

      Find the first X25519 key.

   .. method:: find_pq() -> Key | None

      Find the first post-quantum key.

   .. method:: find_dh() -> Key | None

      Find the first DH key.

   .. method:: add_trusted_cert(der: bytes) -> None

      Add a trusted DER-encoded X.509 certificate.

   .. method:: add_untrusted_cert(der: bytes) -> None

      Add an untrusted DER-encoded X.509 certificate.

   .. method:: add_crl(der: bytes) -> None

      Add a DER-encoded CRL.

   .. method:: trusted_certs() -> list[bytes]

      Return the trusted certificates as a list of DER bytes.

   .. method:: untrusted_certs() -> list[bytes]

      Return the untrusted certificates as a list of DER bytes.

   .. method:: crls() -> list[bytes]

      Return the CRLs as a list of DER bytes.

   .. method:: has_trusted_certs() -> bool

      Whether the manager has any trusted certificates.

Key loaders
-----------

File-based loaders
^^^^^^^^^^^^^^^^^^

.. function:: load_key_file(path: str) -> Key

   Load a key from a file, auto-detecting the format by extension
   (``.pem``, ``.der``, ``.cer``, ``.p12``, etc.).

   :raises KeyLoadError: If the file cannot be read or parsed.

   .. code-block:: python

      key = pybergshamra.load_key_file("rsakey.pem")

.. function:: load_key_file_with_password(path: str, password: str) -> Key

   Load a key from a password-protected file.

   :raises KeyLoadError: If the file cannot be read, the password is wrong,
       or the format is unsupported.

   .. code-block:: python

      key = pybergshamra.load_key_file_with_password("cakey.pem", "secret123")

.. function:: load_pkcs12(data: bytes, password: str) -> Key

   Load a key from PKCS#12 (PFX) data with a password.

   :param data: Raw PKCS#12 bytes.
   :param password: The password protecting the PKCS#12 file.
   :raises KeyLoadError: If the data is invalid or the password is wrong.

   .. code-block:: python

      p12_data = open("key.p12", "rb").read()
      key = pybergshamra.load_pkcs12(p12_data, "secret123")

.. function:: load_keys_file(path: str) -> list[Key]

   Load keys from an xmlsec ``keys.xml`` file.

   :raises KeyLoadError: If the file cannot be read or parsed.

   .. code-block:: python

      keys = pybergshamra.load_keys_file("keys.xml")
      for key in keys:
          print(key.name, key.algorithm_name)

RSA loaders
^^^^^^^^^^^

.. function:: load_rsa_private_pem(pem_data: bytes) -> Key

   Load an RSA private key from PEM data.

   :raises KeyLoadError: If the PEM data is not a valid RSA private key.

.. function:: load_rsa_public_pem(pem_data: bytes) -> Key

   Load an RSA public key from PEM data.

   :raises KeyLoadError: If the PEM data is not a valid RSA public key.

EC loaders
^^^^^^^^^^

.. function:: load_ec_p256_private_pem(pem_data: bytes) -> Key

   Load an EC P-256 (secp256r1) private key from PEM data.

   :raises KeyLoadError: If the PEM data is not a valid EC P-256 key.

.. function:: load_ec_p384_private_pem(pem_data: bytes) -> Key

   Load an EC P-384 (secp384r1) private key from PEM data.

   :raises KeyLoadError: If the PEM data is not a valid EC P-384 key.

.. function:: load_ec_p521_private_pem(pem_data: bytes) -> Key

   Load an EC P-521 (secp521r1) private key from PEM data.

   :raises KeyLoadError: If the PEM data is not a valid EC P-521 key.

X.509 loaders
^^^^^^^^^^^^^

.. function:: load_x509_cert_pem(pem_data: bytes) -> Key

   Load an X.509 certificate from PEM data. The returned key contains
   the certificate's public key and the certificate chain.

   :raises KeyLoadError: If the PEM data is not a valid certificate.

   .. code-block:: python

      cert_pem = open("cert.pem", "rb").read()
      key = pybergshamra.load_x509_cert_pem(cert_pem)
      print(key.algorithm_name)  # e.g. "RSA"
      print(len(key.x509_chain))  # 1

.. function:: load_x509_cert_der(data: bytes) -> Key

   Load an X.509 certificate from DER data.

   :raises KeyLoadError: If the data is not a valid DER certificate.

Symmetric key loaders
^^^^^^^^^^^^^^^^^^^^^

.. function:: load_hmac_key(data: bytes) -> Key

   Create an HMAC key from raw bytes. This function never fails.

   .. code-block:: python

      key = pybergshamra.load_hmac_key(b"my-secret-key")
      print(key.algorithm_name)  # "HMAC"

.. function:: load_aes_key(data: bytes) -> Key

   Create an AES key from raw bytes. The data length must be 16 (AES-128),
   24 (AES-192), or 32 (AES-256) bytes.

   :raises KeyLoadError: If the data length is invalid.

   .. code-block:: python

      import os
      key = pybergshamra.load_aes_key(os.urandom(32))  # AES-256

.. function:: load_des3_key(data: bytes) -> Key

   Create a 3DES key from raw bytes. The data must be 24 bytes.

   :raises KeyLoadError: If the data length is not 24.

Auto-detect loaders
^^^^^^^^^^^^^^^^^^^

.. function:: load_pem_auto(pem_data: bytes, password: str | None = None) -> Key

   Auto-detect the PEM type and load the key. Handles RSA, EC, Ed25519,
   X.509 certificates, PKCS#8, and encrypted PEM.

   :param pem_data: PEM-encoded key or certificate bytes.
   :param password: Optional password for encrypted PEM files.
   :raises KeyLoadError: If the PEM type cannot be determined or loaded.

   .. code-block:: python

      # Works with any PEM type
      key = pybergshamra.load_pem_auto(open("some-key.pem", "rb").read())

      # With password for encrypted PEM
      key = pybergshamra.load_pem_auto(open("cakey.pem", "rb").read(), password="secret123")

SPKI loaders
^^^^^^^^^^^^

.. function:: load_spki_pem(pem_data: bytes) -> Key

   Load a public key from SPKI (Subject Public Key Info) PEM data.

   :raises KeyLoadError: If the PEM data is not valid SPKI.

.. function:: load_spki_der(data: bytes) -> Key

   Load a public key from SPKI DER data.

   :raises KeyLoadError: If the data is not valid SPKI DER.

Ed25519 loaders
^^^^^^^^^^^^^^^

.. function:: load_ed25519_private_pkcs8_der(data: bytes) -> Key

   Load an Ed25519 private key from PKCS#8 DER data.

   :raises KeyLoadError: If the data is not a valid Ed25519 PKCS#8 key.

.. function:: load_ed25519_public_spki_der(data: bytes) -> Key

   Load an Ed25519 public key from SPKI DER data.

   :raises KeyLoadError: If the data is not a valid Ed25519 SPKI key.

X25519 loaders
^^^^^^^^^^^^^^

.. function:: load_x25519_private_raw(data: bytes) -> Key

   Load an X25519 private key from raw 32-byte data.

   :raises KeyLoadError: If the data is not exactly 32 bytes.

.. function:: load_x25519_public_raw(data: bytes) -> Key

   Load an X25519 public key from raw 32-byte data.

   :raises KeyLoadError: If the data is not exactly 32 bytes.

Keys XML
^^^^^^^^

.. function:: parse_keys_xml(xml: str) -> list[Key]

   Parse keys from an xmlsec ``keys.xml`` string.

   :raises KeyLoadError: If the XML is not a valid keys document.

   .. code-block:: python

      xml = open("keys.xml").read()
      keys = pybergshamra.parse_keys_xml(xml)
      for k in keys:
          print(k.name, k.algorithm_name)

X509 KeyInfo builders
---------------------

.. function:: build_x509_key_info(certs_b64: list[str]) -> str

   Build a ``<ds:KeyInfo><ds:X509Data>`` XML fragment from base64-encoded
   certificates.

   :param certs_b64: List of base64-encoded certificate strings.
   :returns: XML string with ``ds:`` namespace prefix.

   .. code-block:: python

      import base64
      cert_der = open("cert.der", "rb").read()
      cert_b64 = base64.b64encode(cert_der).decode()
      xml = pybergshamra.build_x509_key_info([cert_b64])
      # '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>...</ds:X509Certificate></ds:X509Data></ds:KeyInfo>'

.. function:: build_x509_key_info_from_der(certs_der: list[bytes]) -> str

   Build a ``<ds:KeyInfo><ds:X509Data>`` XML fragment from DER-encoded
   certificates.

   :param certs_der: List of DER-encoded certificate bytes.
   :returns: XML string with ``ds:`` namespace prefix.

   .. code-block:: python

      cert_der = open("cert.der", "rb").read()
      xml = pybergshamra.build_x509_key_info_from_der([cert_der])

Digital signatures
------------------

DsigContext
^^^^^^^^^^^

.. class:: DsigContext(keys_manager: KeysManager)

   Context for XML Digital Signature operations. Holds configuration and a
   :class:`KeysManager`. Build one, set properties, then call :func:`verify`
   or :func:`sign`.

   :param keys_manager: The key store to use for sign/verify operations.

   .. code-block:: python

      manager = pybergshamra.KeysManager()
      manager.add_key(key)
      ctx = pybergshamra.DsigContext(manager)

   .. attribute:: debug
      :type: bool

      Debug mode: print pre-digest and pre-signature data to stderr.
      Default: ``False``.

   .. attribute:: insecure
      :type: bool

      Insecure mode: skip certificate validation. Default: ``False``.

   .. attribute:: verify_keys
      :type: bool

      Whether to validate certificates for keys loaded from files.
      Default: ``False``.

   .. attribute:: verification_time
      :type: str | None

      Verification time override. Format: ``"YYYY-MM-DD+HH:MM:SS"``.
      Default: ``None`` (use current time).

   .. attribute:: skip_time_checks
      :type: bool

      Skip X.509 NotBefore/NotAfter validation. Default: ``False``.

   .. attribute:: enabled_key_data_x509
      :type: bool

      Whether enabled key data includes X.509. Default: ``False``.

   .. attribute:: trusted_keys_only
      :type: bool

      Only use pre-configured keys, skip inline KeyInfo extraction.
      Default: ``False``.

   .. attribute:: strict_verification
      :type: bool

      Enforce strict reference target validation (anti-XSW protection).
      Default: ``False``.

      .. code-block:: python

         ctx = pybergshamra.DsigContext(manager)
         ctx.strict_verification = True
         result = pybergshamra.verify(ctx, xml)

   .. attribute:: hmac_min_out_len
      :type: int

      Minimum HMAC output length in bits. ``0`` means use the spec default.

   .. attribute:: base_dir
      :type: str | None

      Base directory for resolving relative external URIs.

   .. method:: add_id_attr(name: str) -> None

      Register an additional ID attribute name. Required for SAML and other
      XML formats that use custom ID attributes (e.g. ``"ID"``).

      .. code-block:: python

         ctx = pybergshamra.DsigContext(manager)
         ctx.add_id_attr("ID")  # needed for SAML
         result = pybergshamra.verify(ctx, saml_xml)

   .. method:: add_url_map(url: str, file_path: str) -> None

      Map a URL to a local file path for external URI resolution.

      .. code-block:: python

         ctx.add_url_map("http://example.com/schema.xsd", "/local/schema.xsd")

VerifyResult
^^^^^^^^^^^^

.. class:: VerifyResult

   Result of signature verification. Use ``bool(result)`` to check validity.

   .. attribute:: is_valid
      :type: bool

      Whether the signature is valid.

   .. attribute:: reason
      :type: str | None

      The reason for invalidity, or ``None`` if valid.

   .. attribute:: references
      :type: list[VerifiedReference] | None

      The verified references, or ``None`` if invalid.

   .. attribute:: key_info
      :type: VerifiedKeyInfo | None

      Information about the verification key, or ``None`` if invalid.

   .. attribute:: signature_node_id
      :type: int | None

      The node ID of the ``<Signature>`` element, or ``None`` if invalid.

   .. code-block:: python

      result = pybergshamra.verify(ctx, xml)
      if result:
          print("Valid!")
          for ref in result.references:
              print(f"  Reference URI: {ref.uri}")
          print(f"  Key algorithm: {result.key_info.algorithm}")
      else:
          print(f"Invalid: {result.reason}")

VerifiedReference
^^^^^^^^^^^^^^^^^

.. class:: VerifiedReference

   Metadata about a single verified ``<Reference>`` element.

   .. attribute:: uri
      :type: str

      The URI attribute from the ``<Reference>`` element.

   .. attribute:: resolved_node_id
      :type: int | None

      The resolved target node ID (if a same-document reference).

VerifiedKeyInfo
^^^^^^^^^^^^^^^

.. class:: VerifiedKeyInfo

   Information about the key used for verification.

   .. attribute:: algorithm
      :type: str

      Algorithm name (e.g. ``"RSA"``, ``"EC-P256"``, ``"HMAC"``).

   .. attribute:: key_name
      :type: str | None

      Key name (if resolved by name from KeysManager).

   .. attribute:: x509_chain
      :type: list[bytes]

      DER-encoded X.509 certificate chain (leaf first).

verify and sign
^^^^^^^^^^^^^^^

.. function:: verify(ctx: DsigContext, xml: str) -> VerifyResult

   Verify a signed XML document. Returns a :class:`VerifyResult` -- use
   ``bool(result)`` to check validity.

   :param ctx: A configured :class:`DsigContext`.
   :param xml: The signed XML string.
   :raises XmlError: If the XML cannot be parsed.

   .. code-block:: python

      result = pybergshamra.verify(ctx, xml)
      if result:
          print("Signature valid")

.. function:: sign(ctx: DsigContext, template_xml: str) -> str

   Sign an XML template and return the signed XML string. The template must
   contain a ``<Signature>`` skeleton with ``<SignedInfo>``, ``<Reference>``,
   etc.

   :param ctx: A configured :class:`DsigContext`.
   :param template_xml: The XML template string.
   :raises XmlError: If the XML template cannot be parsed.
   :raises CryptoError: If signing fails.

   .. code-block:: python

      signed_xml = pybergshamra.sign(ctx, template)
      print(signed_xml)

XML encryption
--------------

EncContext
^^^^^^^^^^

.. class:: EncContext(keys_manager: KeysManager)

   Context for XML Encryption operations. Holds configuration and a
   :class:`KeysManager`.

   :param keys_manager: The key store to use for encrypt/decrypt operations.

   .. attribute:: disable_cipher_reference
      :type: bool

      Whether CipherReference resolution is disabled. Default: ``False``.

   .. method:: add_id_attr(name: str) -> None

      Register an additional ID attribute name.

encrypt, decrypt, decrypt_to_bytes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. function:: encrypt(ctx: EncContext, template_xml: str, data: bytes) -> str

   Encrypt data using an XML template. The template must contain an
   ``<EncryptedData>`` element with an empty ``<CipherValue>``.

   :param ctx: A configured :class:`EncContext`.
   :param template_xml: The XML encryption template.
   :param data: The plaintext bytes to encrypt.
   :returns: XML string with encrypted content.
   :raises EncryptionError: If encryption fails.

.. function:: decrypt(ctx: EncContext, xml: str) -> str

   Decrypt an XML document containing ``<EncryptedData>``. Returns the
   decrypted XML as a string.

   :param ctx: A configured :class:`EncContext`.
   :param xml: The XML string containing encrypted data.
   :raises EncryptionError: If decryption fails.
   :raises XmlError: If the XML cannot be parsed.

.. function:: decrypt_to_bytes(ctx: EncContext, xml: str) -> bytes

   Decrypt an XML document containing ``<EncryptedData>``. Returns the raw
   decrypted bytes (supports non-UTF-8 content).

   :param ctx: A configured :class:`EncContext`.
   :param xml: The XML string containing encrypted data.
   :raises EncryptionError: If decryption fails.
   :raises XmlError: If the XML cannot be parsed.

Canonicalization
----------------

C14nMode
^^^^^^^^

.. class:: C14nMode

   XML Canonicalization mode enumeration.

   .. attribute:: Inclusive

      Inclusive C14N (``http://www.w3.org/TR/2001/REC-xml-c14n-20010315``)

   .. attribute:: InclusiveWithComments

      Inclusive C14N with comments

   .. attribute:: Inclusive11

      Inclusive C14N 1.1

   .. attribute:: Inclusive11WithComments

      Inclusive C14N 1.1 with comments

   .. attribute:: Exclusive

      Exclusive C14N (``http://www.w3.org/2001/10/xml-exc-c14n#``)

   .. attribute:: ExclusiveWithComments

      Exclusive C14N with comments

   **Properties**

   .. attribute:: uri
      :type: str

      The W3C algorithm URI for this mode.

   .. attribute:: with_comments
      :type: bool

      Whether this mode includes comments.

   .. attribute:: is_exclusive
      :type: bool

      Whether this mode uses exclusive canonicalization.

   **Methods**

   .. staticmethod:: from_uri(uri: str) -> C14nMode | None

      Look up a ``C14nMode`` from its W3C algorithm URI. Returns ``None``
      if the URI is not recognized.

      .. code-block:: python

         from pybergshamra import C14nMode

         mode = C14nMode.from_uri("http://www.w3.org/2001/10/xml-exc-c14n#")
         assert mode == C14nMode.Exclusive

canonicalize and canonicalize_subtree
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. function:: canonicalize(xml: str, mode: C14nMode, inclusive_prefixes: list[str] | None = None) -> bytes

   Canonicalize an XML document.

   :param xml: The XML string.
   :param mode: The canonicalization mode.
   :param inclusive_prefixes: Optional namespace prefixes to force
       visibly-utilized in exclusive C14N.
   :returns: The canonicalized XML as bytes.
   :raises XmlError: If the XML cannot be parsed.

   .. code-block:: python

      from pybergshamra import canonicalize, C14nMode

      result = canonicalize("<b/><a/>", C14nMode.Exclusive)

.. function:: canonicalize_subtree(xml: str, element_id: str, mode: C14nMode, inclusive_prefixes: list[str] | None = None) -> bytes

   Canonicalize a subtree identified by an element ID.

   :param xml: The XML string.
   :param element_id: The ID attribute value of the target element.
   :param mode: The canonicalization mode.
   :param inclusive_prefixes: Optional namespace prefixes.
   :returns: The canonicalized subtree as bytes.
   :raises XmlError: If the XML cannot be parsed or the element is not found.

   .. code-block:: python

      from pybergshamra import canonicalize_subtree, C14nMode

      xml = '<root><item Id="x1">hello</item></root>'
      result = canonicalize_subtree(xml, "x1", C14nMode.Exclusive)

Cryptographic primitives
------------------------

.. function:: digest(algorithm_uri: str, data: bytes) -> bytes

   Compute a one-shot message digest.

   :param algorithm_uri: A W3C algorithm URI (e.g. ``Algorithm.SHA256``).
   :param data: The data to digest.
   :returns: The digest bytes.
   :raises AlgorithmError: If the algorithm is unsupported.

   .. code-block:: python

      from pybergshamra import digest, Algorithm

      h = digest(Algorithm.SHA256, b"hello world")
      print(h.hex())

.. function:: pbkdf2_derive(password: bytes, salt: bytes, iteration_count: int, key_length: int, prf_uri: str) -> bytes

   Derive a key using PBKDF2 (RFC 8018).

   :param password: The password/secret bytes.
   :param salt: Salt bytes.
   :param iteration_count: Number of iterations.
   :param key_length: Desired output key length in bytes.
   :param prf_uri: PRF algorithm URI (e.g. ``Algorithm.HMAC_SHA256``).
   :returns: The derived key bytes.

   .. code-block:: python

      from pybergshamra import pbkdf2_derive, Algorithm

      key = pbkdf2_derive(
          b"password", b"salt", 100_000, 32, Algorithm.HMAC_SHA256
      )

.. function:: hkdf_derive(shared_secret: bytes, key_length: int, prf_uri: str | None = None, salt: bytes | None = None, info: bytes | None = None) -> bytes

   Derive a key using HKDF (RFC 5869).

   :param shared_secret: Input keying material (IKM).
   :param key_length: Desired output key length in bytes.
   :param prf_uri: PRF algorithm URI (default: HMAC-SHA256).
   :param salt: Optional salt bytes.
   :param info: Optional context/info bytes.
   :returns: The derived key bytes.

   .. code-block:: python

      from pybergshamra import hkdf_derive

      key = hkdf_derive(b"shared-secret", 32, salt=b"salt", info=b"context")

.. function:: concat_kdf(shared_secret: bytes, key_length: int, digest_uri: str | None = None, algorithm_id: bytes | None = None, party_u_info: bytes | None = None, party_v_info: bytes | None = None) -> bytes

   Derive a key using ConcatKDF (NIST SP 800-56A).

   :param shared_secret: The shared secret bytes (Z).
   :param key_length: Desired output key length in bytes.
   :param digest_uri: Digest algorithm URI (default: SHA-256).
   :param algorithm_id: Optional AlgorithmID bytes.
   :param party_u_info: Optional PartyUInfo bytes.
   :param party_v_info: Optional PartyVInfo bytes.
   :returns: The derived key bytes.

   .. code-block:: python

      from pybergshamra import concat_kdf

      key = concat_kdf(b"shared-secret", 32)

Certificate validation
----------------------

.. function:: validate_cert_chain(leaf_der: bytes, additional_certs: list[bytes] = [], trusted_certs: list[bytes] = [], untrusted_certs: list[bytes] = [], crls: list[bytes] = [], verification_time: str | None = None, skip_time_checks: bool = False) -> None

   Validate an X.509 certificate chain. Verifies that the leaf certificate
   chains to a trusted root, optionally checking time validity and CRLs.

   :param leaf_der: DER-encoded leaf certificate.
   :param additional_certs: Extra certificates from XML (DER-encoded).
   :param trusted_certs: Trusted CA certificates (DER-encoded).
   :param untrusted_certs: Untrusted intermediate certificates (DER-encoded).
   :param crls: Certificate Revocation Lists (DER-encoded).
   :param verification_time: Time override (format: ``"YYYY-MM-DD+HH:MM:SS"``).
   :param skip_time_checks: Skip NotBefore/NotAfter validation.
   :raises CertificateError: If validation fails.

   Returns ``None`` on success.

   .. code-block:: python

      import pybergshamra

      leaf_der = open("leaf.der", "rb").read()
      ca_der = open("ca.der", "rb").read()

      # Raises CertificateError on failure
      pybergshamra.validate_cert_chain(
          leaf_der,
          trusted_certs=[ca_der],
          skip_time_checks=True,
      )
