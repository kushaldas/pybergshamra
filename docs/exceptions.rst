Exceptions
==========

All pybergshamra exceptions inherit from :class:`BergshamraError`, which itself
inherits from Python's built-in :class:`Exception`.

.. exception:: BergshamraError

   Base exception for all pybergshamra errors. Catch this to handle any error
   from the library.

   .. code-block:: python

      import pybergshamra

      try:
          pybergshamra.verify(ctx, xml)
      except pybergshamra.BergshamraError as e:
          print(f"Something went wrong: {e}")

.. exception:: XmlError

   Raised when XML parsing or structural validation fails -- for example,
   malformed XML input or a missing required element.

   .. code-block:: python

      import pybergshamra

      try:
          pybergshamra.verify(ctx, "<not valid xml")
      except pybergshamra.XmlError as e:
          print(f"XML error: {e}")

.. exception:: CryptoError

   Raised for cryptographic operation failures, including invalid signatures
   and digest mismatches detected during signing or verification setup.

   .. code-block:: python

      import pybergshamra

      try:
          pybergshamra.sign(ctx, template_xml)
      except pybergshamra.CryptoError as e:
          print(f"Crypto error: {e}")

   .. note::

      Signature verification via :func:`verify` returns a :class:`VerifyResult`
      with ``is_valid = False`` rather than raising ``CryptoError``. This exception
      is raised only for unexpected cryptographic failures during the operation.

.. exception:: KeyLoadError

   Raised when a key cannot be loaded -- for example, invalid PEM data, wrong
   password, or unsupported key format.

   .. code-block:: python

      import pybergshamra

      try:
          key = pybergshamra.load_rsa_private_pem(b"not a pem")
      except pybergshamra.KeyLoadError as e:
          print(f"Key load failed: {e}")

.. exception:: AlgorithmError

   Raised when an unsupported or unrecognized algorithm URI is used.

   .. code-block:: python

      import pybergshamra

      try:
          pybergshamra.digest("http://example.com/not-an-algorithm", b"data")
      except pybergshamra.AlgorithmError as e:
          print(f"Unknown algorithm: {e}")

.. exception:: EncryptionError

   Raised when an encryption or decryption operation fails -- for example,
   missing key material, wrong key type, or corrupt ciphertext.

   .. code-block:: python

      import pybergshamra

      try:
          pybergshamra.decrypt(ctx, encrypted_xml)
      except pybergshamra.EncryptionError as e:
          print(f"Decryption failed: {e}")

.. exception:: CertificateError

   Raised when X.509 certificate validation fails -- for example, expired
   certificate, untrusted issuer, or broken chain.

   .. code-block:: python

      import pybergshamra

      try:
          pybergshamra.validate_cert_chain(
              leaf_der, trusted_certs=[ca_der]
          )
      except pybergshamra.CertificateError as e:
          print(f"Certificate invalid: {e}")

Exception hierarchy
-------------------

::

    Exception
    └── BergshamraError
        ├── XmlError
        ├── CryptoError
        ├── KeyLoadError
        ├── AlgorithmError
        ├── EncryptionError
        └── CertificateError
