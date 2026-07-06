Quick start
===========

Installation
------------

Install from PyPI::

    pip install pybergshamra

Or with `uv <https://docs.astral.sh/uv/>`_::

    uv add pybergshamra

Requirements: Python 3.10 or later. No C compiler needed -- the package ships
pre-built wheels compiled from Rust.

Load a key
----------

.. code-block:: python

    import pybergshamra

    # From file (auto-detect format by extension)
    key = pybergshamra.load_key_file("rsakey.pem")

    # RSA private key from PEM bytes
    pem_data = open("rsakey.pem", "rb").read()
    key = pybergshamra.load_rsa_private_pem(pem_data)

    # X.509 certificate from PEM
    cert = pybergshamra.load_x509_cert_pem(open("cert.pem", "rb").read())

    # Auto-detect any PEM type
    key = pybergshamra.load_pem_auto(pem_data)

    # Password-protected key file
    key = pybergshamra.load_key_file_with_password("cakey.pem", "secret123")

Verify a signed XML document
-----------------------------

.. code-block:: python

    import pybergshamra

    xml = open("signed.xml").read()

    # Set up keys
    manager = pybergshamra.KeysManager()
    key = pybergshamra.load_x509_cert_pem(open("cert.pem", "rb").read())
    manager.add_key(key)

    # Verify
    ctx = pybergshamra.DsigContext(manager)
    result = pybergshamra.verify(ctx, xml)

    if result:
        print("Signature is valid")
        print("Algorithm:", result.key_info.algorithm)
    else:
        print("Invalid:", result.reason)

Sign an XML template
--------------------

.. code-block:: python

    import pybergshamra

    template = open("sign-template.xml").read()

    manager = pybergshamra.KeysManager()
    key = pybergshamra.load_rsa_private_pem(open("rsakey.pem", "rb").read())
    manager.add_key(key)

    ctx = pybergshamra.DsigContext(manager)
    signed_xml = pybergshamra.sign(ctx, template)
    print(signed_xml)

Encrypt data
------------

.. code-block:: python

    import pybergshamra

    template = open("enc-template.xml").read()
    plaintext = b"secret data"

    manager = pybergshamra.KeysManager()
    key = pybergshamra.load_x509_cert_pem(open("rsacert.pem", "rb").read())
    manager.add_key(key)

    ctx = pybergshamra.EncContext(manager)
    encrypted_xml = pybergshamra.encrypt(ctx, template, plaintext)

Decrypt data
------------

.. code-block:: python

    import pybergshamra

    encrypted_xml = open("encrypted.xml").read()

    manager = pybergshamra.KeysManager()
    key = pybergshamra.load_rsa_private_pem(open("rsakey.pem", "rb").read())
    manager.add_key(key)

    ctx = pybergshamra.EncContext(manager)
    decrypted_xml = pybergshamra.decrypt(ctx, encrypted_xml)

    # Or get raw bytes (for non-UTF-8 content)
    decrypted_bytes = pybergshamra.decrypt_to_bytes(ctx, encrypted_xml)

Canonicalize XML
----------------

.. code-block:: python

    import pybergshamra
    from pybergshamra import C14nMode

    xml = "<root><b/><a/></root>"

    # Full document
    result = pybergshamra.canonicalize(xml, C14nMode.Exclusive)
    print(result)

    # With inclusive namespace prefixes
    result = pybergshamra.canonicalize(xml, C14nMode.Exclusive, inclusive_prefixes=["ds"])

    # Subtree by element ID
    result = pybergshamra.canonicalize_subtree(xml, "my-element", C14nMode.Exclusive)
