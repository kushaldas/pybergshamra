Examples
========

Verify a SAML Response
----------------------

Load an IdP certificate, register the ``ID`` attribute, and verify:

.. code-block:: python

    import pybergshamra

    saml_xml = open("saml-response.xml").read()

    manager = pybergshamra.KeysManager()
    idp_cert = pybergshamra.load_x509_cert_pem(open("idp-cert.pem", "rb").read())
    manager.add_key(idp_cert)

    ctx = pybergshamra.DsigContext(manager)
    ctx.add_id_attr("ID")  # SAML uses "ID" not "Id"

    result = pybergshamra.verify(ctx, saml_xml)
    if result:
        print("SAML signature valid")
        print(f"  Algorithm: {result.key_info.algorithm}")
        for ref in result.references:
            print(f"  Reference: {ref.uri}")
    else:
        print(f"SAML signature invalid: {result.reason}")

Sign an XML document (enveloped)
--------------------------------

Build a signature template with pyuppsala's ``XmlWriter`` and sign it:

.. code-block:: python

    import pybergshamra
    from pybergshamra import Algorithm
    from pyuppsala import XmlWriter

    DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

    # Build the document with an embedded signature template
    w = XmlWriter()
    w.start_element("Document", [("Id", "doc-1")])

    w.start_element("Data")
    w.text("Important content")
    w.end_element("Data")

    # Signature template
    w.start_element_ns(DSIG_NS, "ds", "Signature")
    w.start_element_ns(DSIG_NS, "ds", "SignedInfo")
    w.start_element_ns(DSIG_NS, "ds", "CanonicalizationMethod",
                       [("Algorithm", Algorithm.EXC_C14N)])
    w.end_element_ns(DSIG_NS, "ds", "CanonicalizationMethod")
    w.start_element_ns(DSIG_NS, "ds", "SignatureMethod",
                       [("Algorithm", Algorithm.RSA_SHA256)])
    w.end_element_ns(DSIG_NS, "ds", "SignatureMethod")
    w.start_element_ns(DSIG_NS, "ds", "Reference", [("URI", "#doc-1")])
    w.start_element_ns(DSIG_NS, "ds", "Transforms")
    w.start_element_ns(DSIG_NS, "ds", "Transform",
                       [("Algorithm", Algorithm.ENVELOPED_SIGNATURE)])
    w.end_element_ns(DSIG_NS, "ds", "Transform")
    w.end_element_ns(DSIG_NS, "ds", "Transforms")
    w.start_element_ns(DSIG_NS, "ds", "DigestMethod",
                       [("Algorithm", Algorithm.SHA256)])
    w.end_element_ns(DSIG_NS, "ds", "DigestMethod")
    w.start_element_ns(DSIG_NS, "ds", "DigestValue")
    w.end_element_ns(DSIG_NS, "ds", "DigestValue")
    w.end_element_ns(DSIG_NS, "ds", "Reference")
    w.end_element_ns(DSIG_NS, "ds", "SignedInfo")
    w.start_element_ns(DSIG_NS, "ds", "SignatureValue")
    w.end_element_ns(DSIG_NS, "ds", "SignatureValue")
    w.end_element_ns(DSIG_NS, "ds", "Signature")

    w.end_element("Document")
    template = w.to_string()

    # Sign
    manager = pybergshamra.KeysManager()
    key = pybergshamra.load_rsa_private_pem(open("rsakey.pem", "rb").read())
    manager.add_key(key)

    ctx = pybergshamra.DsigContext(manager)
    ctx.add_id_attr("Id")
    signed_xml = pybergshamra.sign(ctx, template)
    print(signed_xml)

Sign with HMAC
--------------

.. code-block:: python

    import pybergshamra

    template = open("hmac-sign-template.xml").read()

    manager = pybergshamra.KeysManager()
    key = pybergshamra.load_hmac_key(b"my-shared-secret-key")
    key.name = "hmac-key"
    manager.add_key(key)

    ctx = pybergshamra.DsigContext(manager)
    signed_xml = pybergshamra.sign(ctx, template)

Sign with ECDSA
---------------

.. code-block:: python

    import pybergshamra

    template = open("ec-sign-template.xml").read()

    manager = pybergshamra.KeysManager()
    key = pybergshamra.load_ec_p256_private_pem(open("ec-p256-key.pem", "rb").read())
    manager.add_key(key)

    ctx = pybergshamra.DsigContext(manager)
    signed_xml = pybergshamra.sign(ctx, template)

Encrypt XML with AES-256-GCM + RSA-OAEP
----------------------------------------

Build an encryption template and encrypt data:

.. code-block:: python

    import pybergshamra

    # Load the recipient's public key (from their certificate)
    manager = pybergshamra.KeysManager()
    key = pybergshamra.load_x509_cert_pem(open("recipient-cert.pem", "rb").read())
    manager.add_key(key)

    # Template defines: AES-256-GCM for content, RSA-OAEP for key transport
    template = open("enc-template-aes256gcm-rsa-oaep.xml").read()
    plaintext = b"<secret>Classified information</secret>"

    ctx = pybergshamra.EncContext(manager)
    encrypted_xml = pybergshamra.encrypt(ctx, template, plaintext)
    print(encrypted_xml)

Decrypt an EncryptedAssertion
-----------------------------

.. code-block:: python

    import pybergshamra

    encrypted_xml = open("encrypted-assertion.xml").read()

    manager = pybergshamra.KeysManager()
    key = pybergshamra.load_rsa_private_pem(open("sp-private-key.pem", "rb").read())
    manager.add_key(key)

    ctx = pybergshamra.EncContext(manager)

    # Decrypt to XML string
    decrypted_xml = pybergshamra.decrypt(ctx, encrypted_xml)
    print(decrypted_xml)

    # Or decrypt to raw bytes (useful for non-XML content)
    decrypted_bytes = pybergshamra.decrypt_to_bytes(ctx, encrypted_xml)

Canonicalize a subtree
----------------------

Exclusive C14N with inclusive namespace prefixes, commonly needed for
SAML signature verification:

.. code-block:: python

    import pybergshamra
    from pybergshamra import C14nMode

    xml = """\
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                    ID="assertion-1">
      <saml:Issuer>https://idp.example.com</saml:Issuer>
      <ds:Signature>...</ds:Signature>
      <saml:Subject>...</saml:Subject>
    </saml:Assertion>
    """

    # Canonicalize the full document
    result = pybergshamra.canonicalize(xml, C14nMode.Exclusive)
    print(result.decode())

    # Canonicalize just the Assertion subtree, keeping "saml" prefix visible
    result = pybergshamra.canonicalize_subtree(
        xml, "assertion-1", C14nMode.Exclusive,
        inclusive_prefixes=["saml"]
    )
    print(result.decode())

Certificate chain validation
----------------------------

Validate a leaf certificate against trusted CA certificates:

.. code-block:: python

    import pybergshamra

    leaf_der = open("server-cert.der", "rb").read()
    ca_der = open("ca-cert.der", "rb").read()
    intermediate_der = open("intermediate.der", "rb").read()

    try:
        pybergshamra.validate_cert_chain(
            leaf_der,
            trusted_certs=[ca_der],
            untrusted_certs=[intermediate_der],
        )
        print("Certificate chain is valid")
    except pybergshamra.CertificateError as e:
        print(f"Validation failed: {e}")

    # Skip time checks for testing with expired certs
    pybergshamra.validate_cert_chain(
        leaf_der,
        trusted_certs=[ca_der],
        skip_time_checks=True,
    )

Key derivation
--------------

PBKDF2, HKDF, and ConcatKDF examples:

.. code-block:: python

    import pybergshamra
    from pybergshamra import Algorithm

    # PBKDF2: derive a 256-bit key from a password
    derived = pybergshamra.pbkdf2_derive(
        password=b"my-password",
        salt=b"random-salt-value",
        iteration_count=100_000,
        key_length=32,
        prf_uri=Algorithm.HMAC_SHA256,
    )
    print(f"PBKDF2 key: {derived.hex()}")

    # HKDF: derive a key from shared secret
    derived = pybergshamra.hkdf_derive(
        shared_secret=b"shared-secret-from-key-agreement",
        key_length=32,
        salt=b"application-salt",
        info=b"encryption-context",
    )
    print(f"HKDF key: {derived.hex()}")

    # ConcatKDF: derive a key (NIST SP 800-56A style)
    derived = pybergshamra.concat_kdf(
        shared_secret=b"ecdh-shared-secret",
        key_length=32,
    )
    print(f"ConcatKDF key: {derived.hex()}")

    # Standalone digest
    h = pybergshamra.digest(Algorithm.SHA256, b"data to hash")
    print(f"SHA-256: {h.hex()}")

Ed25519 signatures
------------------

.. code-block:: python

    import pybergshamra

    # Load Ed25519 keys from DER
    private_key = pybergshamra.load_ed25519_private_pkcs8_der(private_der_bytes)
    public_key = pybergshamra.load_ed25519_public_spki_der(public_der_bytes)

    print(private_key.algorithm_name)  # "Ed25519"
    print(private_key.has_private_key)  # True

    # Use in signing
    manager = pybergshamra.KeysManager()
    manager.add_key(private_key)

    ctx = pybergshamra.DsigContext(manager)
    signed_xml = pybergshamra.sign(ctx, template)

    # Verify with public key
    verify_manager = pybergshamra.KeysManager()
    verify_manager.add_key(public_key)

    verify_ctx = pybergshamra.DsigContext(verify_manager)
    result = pybergshamra.verify(verify_ctx, signed_xml)
    assert result.is_valid
