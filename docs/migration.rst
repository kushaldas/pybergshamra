Migrating from python-xmlsec
=============================

Why migrate?
------------

- Zero C dependencies (no libxmlsec1, libxml2, OpenSSL)
- No lxml version mismatch crashes
- Single wheel, works on all platforms
- Post-quantum algorithm support (ML-DSA, SLH-DSA)
- Anti-XSW strict verification mode
- Complete PEP 484 type stubs

Key differences
---------------

- pybergshamra works with XML **strings**, not lxml ``Element`` nodes
- Templates are built with pyuppsala's ``XmlWriter`` (or as raw XML strings)
- Constants use ``Algorithm.RSA_SHA256`` instead of ``xmlsec.Transform.RSA_SHA256``
- Exceptions are typed (``CryptoError``, ``KeyLoadError``, etc.) instead of generic
- Verification returns a ``VerifyResult`` object instead of raising on failure

Key loading
-----------

**xmlsec:**

.. code-block:: python

    import xmlsec

    # From file
    key = xmlsec.Key.from_file("rsakey.pem", xmlsec.KeyFormat.PEM)

    # From memory
    key = xmlsec.Key.from_memory(pem_data, xmlsec.KeyFormat.PEM)

    # With password
    key = xmlsec.Key.from_file("key.pem", xmlsec.KeyFormat.PEM, password="secret")

    # Load certificate onto key
    key.load_cert("rsacert.pem", xmlsec.KeyFormat.CERT_PEM)

    # PKCS#12
    key = xmlsec.Key.from_file("key.p12", xmlsec.KeyFormat.PKCS12, password="pass")

    # HMAC from file
    key = xmlsec.Key.from_binary_file("hmackey.bin")

**pybergshamra:**

.. code-block:: python

    import pybergshamra

    # From file (auto-detect format)
    key = pybergshamra.load_key_file("rsakey.pem")

    # From memory (explicit type)
    key = pybergshamra.load_rsa_private_pem(pem_data)

    # Auto-detect PEM type from memory
    key = pybergshamra.load_pem_auto(pem_data, password="secret")

    # With password
    key = pybergshamra.load_key_file_with_password("key.pem", "secret")

    # X.509 certificate
    key = pybergshamra.load_x509_cert_pem(cert_pem_data)

    # PKCS#12
    key = pybergshamra.load_pkcs12(p12_data, "pass")

    # HMAC from bytes
    key = pybergshamra.load_hmac_key(hmac_bytes)

    # AES key
    key = pybergshamra.load_aes_key(os.urandom(32))  # replaces Key.generate()

KeysManager
-----------

**xmlsec:**

.. code-block:: python

    import xmlsec

    manager = xmlsec.KeysManager()
    key = xmlsec.Key.from_file("rsakey.pem", xmlsec.KeyFormat.PEM)
    manager.add_key(key)

**pybergshamra:**

.. code-block:: python

    import pybergshamra

    manager = pybergshamra.KeysManager()
    key = pybergshamra.load_key_file("rsakey.pem")
    manager.add_key(key)

    # pybergshamra adds typed lookups
    rsa_key = manager.find_rsa()
    ec_key = manager.find_ec_p256()
    named = manager.find_by_name("my-key")

Certificate management
----------------------

**xmlsec:**

.. code-block:: python

    manager = xmlsec.KeysManager()
    key = xmlsec.Key.from_file("cert.pem", xmlsec.KeyFormat.CERT_PEM)
    manager.add_key(key)

**pybergshamra:**

.. code-block:: python

    manager = pybergshamra.KeysManager()
    cert_der = open("cert.der", "rb").read()
    manager.add_trusted_cert(cert_der)
    # Or load as key for signing context
    key = pybergshamra.load_x509_cert_pem(open("cert.pem", "rb").read())
    manager.add_key(key)

Signature verification
----------------------

**xmlsec:**

.. code-block:: python

    from lxml import etree
    import xmlsec

    doc = etree.parse("signed.xml")
    root = doc.getroot()
    signature_node = xmlsec.tree.find_node(root, xmlsec.Node.SIGNATURE)

    ctx = xmlsec.SignatureContext()
    key = xmlsec.Key.from_file("pubkey.pem", xmlsec.KeyFormat.PEM)
    ctx.key = key
    ctx.verify(signature_node)  # raises on failure

**pybergshamra:**

.. code-block:: python

    import pybergshamra

    xml = open("signed.xml").read()

    manager = pybergshamra.KeysManager()
    key = pybergshamra.load_rsa_public_pem(open("pubkey.pem", "rb").read())
    manager.add_key(key)

    ctx = pybergshamra.DsigContext(manager)
    result = pybergshamra.verify(ctx, xml)

    if result:
        print("Valid!", result.key_info.algorithm)
    else:
        print("Invalid:", result.reason)

Signature verification with ID registration
--------------------------------------------

**xmlsec:**

.. code-block:: python

    from lxml import etree
    import xmlsec

    doc = etree.fromstring(saml_xml)
    signature_node = xmlsec.tree.find_node(doc, xmlsec.Node.SIGNATURE)

    ctx = xmlsec.SignatureContext()
    ctx.register_id(doc, "ID")  # register on specific node
    ctx.key = xmlsec.Key.from_file("idp-cert.pem", xmlsec.KeyFormat.CERT_PEM)
    ctx.verify(signature_node)

**pybergshamra:**

.. code-block:: python

    import pybergshamra

    manager = pybergshamra.KeysManager()
    key = pybergshamra.load_x509_cert_pem(open("idp-cert.pem", "rb").read())
    manager.add_key(key)

    ctx = pybergshamra.DsigContext(manager)
    ctx.add_id_attr("ID")  # register attribute name globally
    result = pybergshamra.verify(ctx, saml_xml)

Signing an XML document
-----------------------

**xmlsec:**

.. code-block:: python

    from lxml import etree
    import xmlsec

    # Parse template
    root = etree.parse("document.xml").getroot()

    # Build signature template programmatically
    signature_node = xmlsec.template.create(
        root, xmlsec.Transform.EXCL_C14N, xmlsec.Transform.RSA_SHA256
    )
    root.append(signature_node)

    ref = xmlsec.template.add_reference(signature_node, xmlsec.Transform.SHA256)
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)

    key_info = xmlsec.template.ensure_key_info(signature_node)
    xmlsec.template.add_x509_data(key_info)

    # Sign
    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_file("rsakey.pem", xmlsec.KeyFormat.PEM)
    ctx.sign(signature_node)

    print(etree.tostring(root, encoding="unicode"))

**pybergshamra (with pyuppsala XmlWriter for template):**

.. code-block:: python

    import pybergshamra
    from pyuppsala import XmlWriter

    # Build the template using pyuppsala's XmlWriter
    document_xml = open("document.xml").read()

    # ... (build template XML string with XmlWriter or as a raw string)

    # Sign
    manager = pybergshamra.KeysManager()
    key = pybergshamra.load_rsa_private_pem(open("rsakey.pem", "rb").read())
    manager.add_key(key)

    ctx = pybergshamra.DsigContext(manager)
    signed_xml = pybergshamra.sign(ctx, template_xml)

**pybergshamra (with raw template string):**

.. code-block:: python

    import pybergshamra

    # Pre-built template (e.g. from a file or embedded string)
    template = open("sign-template.xml").read()

    manager = pybergshamra.KeysManager()
    key = pybergshamra.load_rsa_private_pem(open("rsakey.pem", "rb").read())
    manager.add_key(key)

    ctx = pybergshamra.DsigContext(manager)
    signed_xml = pybergshamra.sign(ctx, template)

XML Encryption
--------------

**xmlsec:**

.. code-block:: python

    from lxml import etree
    import xmlsec

    manager = xmlsec.KeysManager()
    key = xmlsec.Key.from_file("rsakey.pem", xmlsec.KeyFormat.PEM)
    manager.add_key(key)

    enc_ctx = xmlsec.EncryptionContext(manager)
    enc_data = xmlsec.tree.find_child(root, "EncryptedData", xmlsec.constants.EncNs)
    decrypted = enc_ctx.decrypt(enc_data)

**pybergshamra:**

.. code-block:: python

    import pybergshamra

    manager = pybergshamra.KeysManager()
    key = pybergshamra.load_rsa_private_pem(open("rsakey.pem", "rb").read())
    manager.add_key(key)

    ctx = pybergshamra.EncContext(manager)
    decrypted_xml = pybergshamra.decrypt(ctx, encrypted_xml_string)

    # Or get raw bytes (for non-UTF-8 content)
    decrypted_bytes = pybergshamra.decrypt_to_bytes(ctx, encrypted_xml_string)

Encryption with template
-------------------------

**xmlsec:**

.. code-block:: python

    from lxml import etree
    import xmlsec

    manager = xmlsec.KeysManager()
    key = xmlsec.Key.from_file("rsacert.pem", xmlsec.KeyFormat.CERT_PEM)
    manager.add_key(key)

    # Build encryption template with xmlsec.template helpers
    enc_data = xmlsec.template.encrypted_data_create(
        root, xmlsec.Transform.AES128_CBC, type=xmlsec.constants.TypeEncContent
    )
    xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
    key_info = xmlsec.template.encrypted_data_ensure_key_info(enc_data)
    enc_key = xmlsec.template.add_encrypted_key(key_info, xmlsec.Transform.RSA_OAEP)

    enc_ctx = xmlsec.EncryptionContext(manager)
    enc_ctx.encrypt_xml(enc_data, element)

**pybergshamra:**

.. code-block:: python

    import pybergshamra

    manager = pybergshamra.KeysManager()
    key = pybergshamra.load_x509_cert_pem(open("rsacert.pem", "rb").read())
    manager.add_key(key)

    # Template built with pyuppsala XmlWriter or as raw XML string
    template_xml = open("enc-template.xml").read()

    ctx = pybergshamra.EncContext(manager)
    encrypted_xml = pybergshamra.encrypt(ctx, template_xml, plaintext_bytes)

Canonicalization
----------------

**xmlsec (via lxml):**

.. code-block:: python

    from lxml import etree

    # lxml provides C14N directly
    root = etree.fromstring(xml_bytes)
    result = etree.tostring(root, method="c14n2")

**pybergshamra:**

.. code-block:: python

    import pybergshamra
    from pybergshamra import C14nMode

    # Full document canonicalization
    result = pybergshamra.canonicalize(xml_string, C14nMode.Exclusive)

    # With inclusive namespace prefixes (common in SAML)
    result = pybergshamra.canonicalize(
        xml_string, C14nMode.Exclusive, inclusive_prefixes=["ds", "saml"]
    )

    # Subtree canonicalization by element ID
    result = pybergshamra.canonicalize_subtree(
        xml_string, "element-id", C14nMode.Exclusive
    )

Algorithm constants
-------------------

**xmlsec:**

.. code-block:: python

    import xmlsec

    xmlsec.Transform.RSA_SHA256
    xmlsec.Transform.EXCL_C14N
    xmlsec.Transform.SHA256
    xmlsec.Transform.ENVELOPED

**pybergshamra:**

.. code-block:: python

    from pybergshamra import Algorithm

    Algorithm.RSA_SHA256
    Algorithm.EXC_C14N
    Algorithm.SHA256
    Algorithm.ENVELOPED_SIGNATURE

    # pybergshamra also has algorithms xmlsec lacks:
    Algorithm.EDDSA_ED25519       # Ed25519
    Algorithm.RSA_PSS_SHA256      # RSA-PSS
    Algorithm.ML_DSA_65           # Post-quantum
    Algorithm.AES256_GCM          # AES-GCM
    Algorithm.ECDH_ES             # Key agreement

Symmetric key generation
------------------------

**xmlsec:**

.. code-block:: python

    import xmlsec

    key = xmlsec.Key.generate(xmlsec.KeyData.AES, 256)

**pybergshamra:**

.. code-block:: python

    import os
    import pybergshamra

    key = pybergshamra.load_aes_key(os.urandom(32))  # 256-bit AES

Error handling
--------------

**xmlsec:**

.. code-block:: python

    import xmlsec

    try:
        ctx.verify(sig_node)
    except xmlsec.Error as e:
        print(f"Verification failed: {e}")

**pybergshamra:**

.. code-block:: python

    import pybergshamra
    from pybergshamra import CryptoError, KeyLoadError, XmlError

    # Verification returns a result object (no exception on invalid signature)
    result = pybergshamra.verify(ctx, xml)
    if not result:
        print(f"Invalid: {result.reason}")

    # Typed exceptions for actual errors
    try:
        key = pybergshamra.load_rsa_private_pem(b"not a pem")
    except KeyLoadError as e:
        print(f"Key load failed: {e}")

    try:
        pybergshamra.verify(ctx, "<not valid xml")
    except XmlError as e:
        print(f"XML parse error: {e}")

Features only in pybergshamra
-----------------------------

These features have no xmlsec equivalent:

.. code-block:: python

    import pybergshamra
    from pybergshamra import Algorithm

    # Post-quantum signatures (ML-DSA, SLH-DSA)
    Algorithm.ML_DSA_44
    Algorithm.ML_DSA_65
    Algorithm.ML_DSA_87
    Algorithm.SLH_DSA_SHA2_128F

    # Ed25519 signing
    key = pybergshamra.load_ed25519_private_pkcs8_der(der_bytes)

    # X25519 key agreement
    key = pybergshamra.load_x25519_private_raw(raw_32_bytes)

    # Key derivation functions
    derived = pybergshamra.pbkdf2_derive(password, salt, 100000, 32, Algorithm.HMAC_SHA256)
    derived = pybergshamra.hkdf_derive(shared_secret, 32, salt=salt, info=info)
    derived = pybergshamra.concat_kdf(shared_secret, 32)

    # Standalone digest
    h = pybergshamra.digest(Algorithm.SHA256, data)

    # Certificate chain validation
    pybergshamra.validate_cert_chain(
        leaf_der, trusted_certs=[ca_der], skip_time_checks=True
    )

    # Anti-XSW strict verification
    ctx = pybergshamra.DsigContext(manager)
    ctx.strict_verification = True

    # Key export
    spki = key.to_spki_der()
    raw = key.symmetric_key_bytes()
    xml_fragment = key.to_key_value_xml()

    # X509 KeyInfo builder
    xml = pybergshamra.build_x509_key_info(["base64cert..."])
