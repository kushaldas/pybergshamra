//! Algorithm URI constants — exposes all W3C XML Security algorithm URIs.

#![allow(non_snake_case)]

use bergshamra_core::algorithm;
use pyo3::prelude::*;

/// W3C XML Security algorithm URI constants.
///
/// Use these instead of hardcoding URI strings in Python code.
/// Example: ``Algorithm.SHA256`` returns the SHA-256 digest URI.
#[pyclass(name = "Algorithm")]
pub struct Algorithm;

#[pymethods]
impl Algorithm {
    // -- Canonicalization (6) -------------------------------------------------
    #[classattr]
    fn C14N() -> &'static str {
        algorithm::C14N
    }
    #[classattr]
    fn C14N_WITH_COMMENTS() -> &'static str {
        algorithm::C14N_WITH_COMMENTS
    }
    #[classattr]
    fn C14N11() -> &'static str {
        algorithm::C14N11
    }
    #[classattr]
    fn C14N11_WITH_COMMENTS() -> &'static str {
        algorithm::C14N11_WITH_COMMENTS
    }
    #[classattr]
    fn EXC_C14N() -> &'static str {
        algorithm::EXC_C14N
    }
    #[classattr]
    fn EXC_C14N_WITH_COMMENTS() -> &'static str {
        algorithm::EXC_C14N_WITH_COMMENTS
    }

    // -- Digest (11) ----------------------------------------------------------
    #[classattr]
    fn SHA1() -> &'static str {
        algorithm::SHA1
    }
    #[classattr]
    fn SHA224() -> &'static str {
        algorithm::SHA224
    }
    #[classattr]
    fn SHA256() -> &'static str {
        algorithm::SHA256
    }
    #[classattr]
    fn SHA384() -> &'static str {
        algorithm::SHA384
    }
    #[classattr]
    fn SHA512() -> &'static str {
        algorithm::SHA512
    }
    #[classattr]
    fn SHA3_224() -> &'static str {
        algorithm::SHA3_224
    }
    #[classattr]
    fn SHA3_256() -> &'static str {
        algorithm::SHA3_256
    }
    #[classattr]
    fn SHA3_384() -> &'static str {
        algorithm::SHA3_384
    }
    #[classattr]
    fn SHA3_512() -> &'static str {
        algorithm::SHA3_512
    }
    #[classattr]
    fn MD5() -> &'static str {
        algorithm::MD5
    }
    #[classattr]
    fn RIPEMD160() -> &'static str {
        algorithm::RIPEMD160
    }

    // -- RSA Signature (7) ----------------------------------------------------
    #[classattr]
    fn RSA_SHA1() -> &'static str {
        algorithm::RSA_SHA1
    }
    #[classattr]
    fn RSA_SHA224() -> &'static str {
        algorithm::RSA_SHA224
    }
    #[classattr]
    fn RSA_SHA256() -> &'static str {
        algorithm::RSA_SHA256
    }
    #[classattr]
    fn RSA_SHA384() -> &'static str {
        algorithm::RSA_SHA384
    }
    #[classattr]
    fn RSA_SHA512() -> &'static str {
        algorithm::RSA_SHA512
    }
    #[classattr]
    fn RSA_MD5() -> &'static str {
        algorithm::RSA_MD5
    }
    #[classattr]
    fn RSA_RIPEMD160() -> &'static str {
        algorithm::RSA_RIPEMD160
    }

    // -- RSA-PSS Signature (9) ------------------------------------------------
    #[classattr]
    fn RSA_PSS_SHA1() -> &'static str {
        algorithm::RSA_PSS_SHA1
    }
    #[classattr]
    fn RSA_PSS_SHA224() -> &'static str {
        algorithm::RSA_PSS_SHA224
    }
    #[classattr]
    fn RSA_PSS_SHA256() -> &'static str {
        algorithm::RSA_PSS_SHA256
    }
    #[classattr]
    fn RSA_PSS_SHA384() -> &'static str {
        algorithm::RSA_PSS_SHA384
    }
    #[classattr]
    fn RSA_PSS_SHA512() -> &'static str {
        algorithm::RSA_PSS_SHA512
    }
    #[classattr]
    fn RSA_PSS_SHA3_224() -> &'static str {
        algorithm::RSA_PSS_SHA3_224
    }
    #[classattr]
    fn RSA_PSS_SHA3_256() -> &'static str {
        algorithm::RSA_PSS_SHA3_256
    }
    #[classattr]
    fn RSA_PSS_SHA3_384() -> &'static str {
        algorithm::RSA_PSS_SHA3_384
    }
    #[classattr]
    fn RSA_PSS_SHA3_512() -> &'static str {
        algorithm::RSA_PSS_SHA3_512
    }

    // -- DSA Signature (2) ----------------------------------------------------
    #[classattr]
    fn DSA_SHA1() -> &'static str {
        algorithm::DSA_SHA1
    }
    #[classattr]
    fn DSA_SHA256() -> &'static str {
        algorithm::DSA_SHA256
    }

    // -- ECDSA Signature (10) -------------------------------------------------
    #[classattr]
    fn ECDSA_SHA1() -> &'static str {
        algorithm::ECDSA_SHA1
    }
    #[classattr]
    fn ECDSA_SHA224() -> &'static str {
        algorithm::ECDSA_SHA224
    }
    #[classattr]
    fn ECDSA_SHA256() -> &'static str {
        algorithm::ECDSA_SHA256
    }
    #[classattr]
    fn ECDSA_SHA384() -> &'static str {
        algorithm::ECDSA_SHA384
    }
    #[classattr]
    fn ECDSA_SHA512() -> &'static str {
        algorithm::ECDSA_SHA512
    }
    #[classattr]
    fn ECDSA_SHA3_224() -> &'static str {
        algorithm::ECDSA_SHA3_224
    }
    #[classattr]
    fn ECDSA_SHA3_256() -> &'static str {
        algorithm::ECDSA_SHA3_256
    }
    #[classattr]
    fn ECDSA_SHA3_384() -> &'static str {
        algorithm::ECDSA_SHA3_384
    }
    #[classattr]
    fn ECDSA_SHA3_512() -> &'static str {
        algorithm::ECDSA_SHA3_512
    }
    #[classattr]
    fn ECDSA_RIPEMD160() -> &'static str {
        algorithm::ECDSA_RIPEMD160
    }

    // -- EdDSA Signature (1) --------------------------------------------------
    #[classattr]
    fn EDDSA_ED25519() -> &'static str {
        algorithm::EDDSA_ED25519
    }

    // -- HMAC Signature (7) ---------------------------------------------------
    #[classattr]
    fn HMAC_SHA1() -> &'static str {
        algorithm::HMAC_SHA1
    }
    #[classattr]
    fn HMAC_SHA224() -> &'static str {
        algorithm::HMAC_SHA224
    }
    #[classattr]
    fn HMAC_SHA256() -> &'static str {
        algorithm::HMAC_SHA256
    }
    #[classattr]
    fn HMAC_SHA384() -> &'static str {
        algorithm::HMAC_SHA384
    }
    #[classattr]
    fn HMAC_SHA512() -> &'static str {
        algorithm::HMAC_SHA512
    }
    #[classattr]
    fn HMAC_MD5() -> &'static str {
        algorithm::HMAC_MD5
    }
    #[classattr]
    fn HMAC_RIPEMD160() -> &'static str {
        algorithm::HMAC_RIPEMD160
    }

    // -- ML-DSA Post-Quantum (3) ----------------------------------------------
    #[classattr]
    fn ML_DSA_44() -> &'static str {
        algorithm::ML_DSA_44
    }
    #[classattr]
    fn ML_DSA_65() -> &'static str {
        algorithm::ML_DSA_65
    }
    #[classattr]
    fn ML_DSA_87() -> &'static str {
        algorithm::ML_DSA_87
    }

    // -- SLH-DSA Post-Quantum (6) ---------------------------------------------
    #[classattr]
    fn SLH_DSA_SHA2_128F() -> &'static str {
        algorithm::SLH_DSA_SHA2_128F
    }
    #[classattr]
    fn SLH_DSA_SHA2_128S() -> &'static str {
        algorithm::SLH_DSA_SHA2_128S
    }
    #[classattr]
    fn SLH_DSA_SHA2_192F() -> &'static str {
        algorithm::SLH_DSA_SHA2_192F
    }
    #[classattr]
    fn SLH_DSA_SHA2_192S() -> &'static str {
        algorithm::SLH_DSA_SHA2_192S
    }
    #[classattr]
    fn SLH_DSA_SHA2_256F() -> &'static str {
        algorithm::SLH_DSA_SHA2_256F
    }
    #[classattr]
    fn SLH_DSA_SHA2_256S() -> &'static str {
        algorithm::SLH_DSA_SHA2_256S
    }

    // -- Block Cipher (7) -----------------------------------------------------
    #[classattr]
    fn AES128_CBC() -> &'static str {
        algorithm::AES128_CBC
    }
    #[classattr]
    fn AES192_CBC() -> &'static str {
        algorithm::AES192_CBC
    }
    #[classattr]
    fn AES256_CBC() -> &'static str {
        algorithm::AES256_CBC
    }
    #[classattr]
    fn AES128_GCM() -> &'static str {
        algorithm::AES128_GCM
    }
    #[classattr]
    fn AES192_GCM() -> &'static str {
        algorithm::AES192_GCM
    }
    #[classattr]
    fn AES256_GCM() -> &'static str {
        algorithm::AES256_GCM
    }
    #[classattr]
    fn TRIPLEDES_CBC() -> &'static str {
        algorithm::TRIPLEDES_CBC
    }

    // -- Key Wrap (4) ---------------------------------------------------------
    #[classattr]
    fn KW_AES128() -> &'static str {
        algorithm::KW_AES128
    }
    #[classattr]
    fn KW_AES192() -> &'static str {
        algorithm::KW_AES192
    }
    #[classattr]
    fn KW_AES256() -> &'static str {
        algorithm::KW_AES256
    }
    #[classattr]
    fn KW_TRIPLEDES() -> &'static str {
        algorithm::KW_TRIPLEDES
    }

    // -- Key Transport (3) ----------------------------------------------------
    #[classattr]
    fn RSA_PKCS1() -> &'static str {
        algorithm::RSA_PKCS1
    }
    #[classattr]
    fn RSA_OAEP() -> &'static str {
        algorithm::RSA_OAEP
    }
    #[classattr]
    fn RSA_OAEP_ENC11() -> &'static str {
        algorithm::RSA_OAEP_ENC11
    }

    // -- MGF (5) --------------------------------------------------------------
    #[classattr]
    fn MGF1_SHA1() -> &'static str {
        algorithm::MGF1_SHA1
    }
    #[classattr]
    fn MGF1_SHA224() -> &'static str {
        algorithm::MGF1_SHA224
    }
    #[classattr]
    fn MGF1_SHA256() -> &'static str {
        algorithm::MGF1_SHA256
    }
    #[classattr]
    fn MGF1_SHA384() -> &'static str {
        algorithm::MGF1_SHA384
    }
    #[classattr]
    fn MGF1_SHA512() -> &'static str {
        algorithm::MGF1_SHA512
    }

    // -- Key Agreement (3) ----------------------------------------------------
    #[classattr]
    fn DH_ES() -> &'static str {
        algorithm::DH_ES
    }
    #[classattr]
    fn ECDH_ES() -> &'static str {
        algorithm::ECDH_ES
    }
    #[classattr]
    fn X25519() -> &'static str {
        algorithm::X25519
    }

    // -- Key Derivation (3) ---------------------------------------------------
    #[classattr]
    fn PBKDF2() -> &'static str {
        algorithm::PBKDF2
    }
    #[classattr]
    fn CONCAT_KDF() -> &'static str {
        algorithm::CONCAT_KDF
    }
    #[classattr]
    fn HKDF() -> &'static str {
        algorithm::HKDF
    }

    // -- Transform (7) --------------------------------------------------------
    #[classattr]
    fn BASE64() -> &'static str {
        algorithm::BASE64
    }
    #[classattr]
    fn ENVELOPED_SIGNATURE() -> &'static str {
        algorithm::ENVELOPED_SIGNATURE
    }
    #[classattr]
    fn XPATH() -> &'static str {
        algorithm::XPATH
    }
    #[classattr]
    fn XPATH2() -> &'static str {
        algorithm::XPATH2
    }
    #[classattr]
    fn XSLT() -> &'static str {
        algorithm::XSLT
    }
    #[classattr]
    fn XPOINTER() -> &'static str {
        algorithm::XPOINTER
    }
    #[classattr]
    fn RELATIONSHIP() -> &'static str {
        algorithm::RELATIONSHIP
    }

    // -- KeyValue Type (5) ----------------------------------------------------
    #[classattr]
    fn RSA_KEY_VALUE() -> &'static str {
        algorithm::RSA_KEY_VALUE
    }
    #[classattr]
    fn DSA_KEY_VALUE() -> &'static str {
        algorithm::DSA_KEY_VALUE
    }
    #[classattr]
    fn EC_KEY_VALUE() -> &'static str {
        algorithm::EC_KEY_VALUE
    }
    #[classattr]
    fn DH_KEY_VALUE() -> &'static str {
        algorithm::DH_KEY_VALUE
    }
    #[classattr]
    fn DER_ENCODED_KEY_VALUE() -> &'static str {
        algorithm::DER_ENCODED_KEY_VALUE
    }

    // -- X509 (2) -------------------------------------------------------------
    #[classattr]
    fn X509_DATA() -> &'static str {
        algorithm::X509_DATA
    }
    #[classattr]
    fn RAW_X509_CERT() -> &'static str {
        algorithm::RAW_X509_CERT
    }

    // -- Encrypted/Derived Key (2) --------------------------------------------
    #[classattr]
    fn ENCRYPTED_KEY() -> &'static str {
        algorithm::ENCRYPTED_KEY
    }
    #[classattr]
    fn DERIVED_KEY() -> &'static str {
        algorithm::DERIVED_KEY
    }
}
