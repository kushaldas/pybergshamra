#!/bin/bash
# Set up a SoftHSM2 test token for pybergshamra's PKCS#11 integration tests.
#
# Mirrors bergshamra's hsm-test/setup.sh: it writes a gitignored, machine-local
# SoftHSM2 config (softhsm2.local.conf) pointing at this checkout's token
# directory, initializes a token, and generates the keys the tests look up by
# label. Re-runnable; it wipes and recreates the token each time.
#
# Usage:  bash hsm-test/setup.sh
# Then:   SOFTHSM2_CONF=hsm-test/softhsm2.local.conf pytest tests/test_hsm.py
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONF="$SCRIPT_DIR/softhsm2.local.conf"
export SOFTHSM2_CONF="$CONF"
TOKEN_DIR="$SCRIPT_DIR/tokens"

# Resolve the SoftHSM2 PKCS#11 module across distros (same candidate list the
# Python tests probe in tests/test_hsm.py).
MODULE=""
for candidate in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib64/softhsm/libsofthsm2.so \
    /usr/local/lib/softhsm/libsofthsm2.so; do
    if [ -f "$candidate" ]; then
        MODULE="$candidate"
        break
    fi
done
if [ -z "$MODULE" ]; then
    echo "ERROR: SoftHSM2 PKCS#11 module (libsofthsm2.so) not found." >&2
    echo "       Install SoftHSM2 + OpenSC (e.g. 'apt install softhsm2 opensc')." >&2
    exit 1
fi
echo "Using SoftHSM2 module: $MODULE"

# SoftHSM2 needs an absolute tokendir and does not expand env vars in its
# config, so write the resolved path into the gitignored local config.
cat > "$CONF" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
log.level = INFO
EOF

rm -rf "$TOKEN_DIR"
mkdir -p "$TOKEN_DIR"

softhsm2-util --init-token --slot 0 --label "pybergshamra-test" --pin 1234 --so-pin 5678

# Provision a second initialized token so the provider tests exercise explicit
# token/slot selection instead of relying on a single visible slot.
softhsm2-util --init-token --free --label "pybergshamra-decoy" --pin 4321 --so-pin 8765

# RSA 2048 key pair (signing + key transport)
pkcs11-tool --module "$MODULE" \
    --login --pin 1234 --token-label "pybergshamra-test" \
    --keypairgen --key-type rsa:2048 --id 01 --label "test-rsa-key"

# RSA 2048 key pair with decrypt usage (RSA-OAEP key transport)
pkcs11-tool --module "$MODULE" \
    --login --pin 1234 --token-label "pybergshamra-test" \
    --keypairgen --key-type rsa:2048 --id 07 --label "test-rsa-enc" \
    --usage-decrypt

# EC P-256 key pair
pkcs11-tool --module "$MODULE" \
    --login --pin 1234 --token-label "pybergshamra-test" \
    --keypairgen --key-type EC:prime256v1 --id 02 --label "test-ec-key"

# HMAC key (256-bit generic secret)
pkcs11-tool --module "$MODULE" \
    --login --pin 1234 --token-label "pybergshamra-test" \
    --keygen --key-type GENERIC:32 --id 05 --label "test-hmac-key" \
    --usage-sign

# AES-256 key (key wrap KEK)
pkcs11-tool --module "$MODULE" \
    --login --pin 1234 --token-label "pybergshamra-test" \
    --keygen --key-type AES:32 --id 06 --label "test-aes-key" \
    --usage-wrap

echo ""
echo "SoftHSM2 test token initialized:"
echo "  Token:    pybergshamra-test   (PIN 1234)"
echo "  Decoy:    pybergshamra-decoy  (PIN 4321)"
echo "  RSA-2048: test-rsa-key  (id 01)  sign/verify"
echo "  RSA-2048: test-rsa-enc  (id 07)  decrypt (RSA-OAEP)"
echo "  EC P-256: test-ec-key   (id 02)"
echo "  HMAC-256: test-hmac-key (id 05)"
echo "  AES-256:  test-aes-key  (id 06)"
echo ""
echo "Run the tests with:"
echo "  SOFTHSM2_CONF=$CONF pytest tests/test_hsm.py -v"
