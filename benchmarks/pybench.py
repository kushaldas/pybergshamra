#!/usr/bin/env python3
"""pybergshamra performance harness (plan.md P0 for the Python layer).

Benchmarks the hot Python-boundary operations against deterministic SAML-shaped
fixtures, plus a threaded wall-clock check that exposes whether the Rust work
holds the GIL. Run the same script against different builds to A/B them:

    maturin develop --release && python3 benchmarks/pybench.py [--json]

The fixture shape matches bergshamra/scripts/gen_fixture.py so Python-layer and
Rust-layer numbers stay comparable.
"""

import argparse
import json
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pybergshamra as p

ASSERTION = (
    '<saml:Assertion ID="_assertion{i}" Version="2.0" '
    'IssueInstant="2026-06-29T12:00:00Z">'
    "<saml:Issuer>https://idp.example.org/metadata</saml:Issuer>"
    "<saml:Subject><saml:NameID "
    'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">'
    "user-{i}@example.org</saml:NameID>"
    '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
    '<saml:SubjectConfirmationData NotOnOrAfter="2026-06-29T12:05:00Z" '
    'Recipient="https://sp.example.org/acs"/></saml:SubjectConfirmation>'
    "</saml:Subject><saml:AttributeStatement>"
    '<saml:Attribute Name="urn:oid:1.2.3.4" '
    'NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">'
    "<saml:AttributeValue>value &amp; {i} &lt; threshold"
    "</saml:AttributeValue></saml:Attribute>"
    "</saml:AttributeStatement></saml:Assertion>"
)

RSA_KEY_PEM = None  # loaded lazily from test-data when present


def document(assertions: int) -> str:
    parts = [
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_response" '
        'Version="2.0" IssueInstant="2026-06-29T12:00:00Z">',
        "<saml:Issuer>https://idp.example.org/metadata</saml:Issuer>",
    ]
    parts.extend(ASSERTION.format(i=i) for i in range(assertions))
    parts.append("</samlp:Response>")
    return "".join(parts)


# Where the human-readable timing rows go. In --json mode they move to stderr
# so stdout carries exactly one JSON document and can be redirected to a file.
ROW_STREAM = sys.stdout


def bench(name, fn, runs=30, warmup=3):
    for _ in range(warmup):
        fn()
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    med = statistics.median(times)
    print(f"{name:<34} {med:>10.3f} ms   (min {min(times):.3f})", file=ROW_STREAM)
    return {"name": name, "median_ms": med, "min_ms": min(times)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    results = {"build_info": {}, "benchmarks": []}

    small = document(40)          # ~30 KB, matches the Rust criterion fixture
    large = document(15_000)      # ~10 MB, matches the memory fixture

    # HMAC keeps the XML pipeline visible (RSA would dominate the total).
    km = p.KeysManager()
    km.add_key(p.load_hmac_key(b"pybench-hmac-secret-0123456789abcdef"))
    ctx = p.DsigContext.permissive(km)

    # Pre-sign fixtures (excluded from measurement).
    signed_small = p.sign_enveloped(
        ctx, small, signature_method=p.Algorithm.HMAC_SHA256
    )
    signed_large = p.sign_enveloped(
        ctx, large, signature_method=p.Algorithm.HMAC_SHA256
    )
    assert p.verify(ctx, signed_small), "fixture must verify"
    assert p.verify(ctx, signed_large), "fixture must verify"

    results["build_info"]["signed_small_bytes"] = len(signed_small)
    results["build_info"]["signed_large_bytes"] = len(signed_large)

    global ROW_STREAM
    if args.json:
        ROW_STREAM = sys.stderr
    else:
        print(f"signed_small: {len(signed_small)} B, signed_large: {len(signed_large)//1024} KiB")
        print()

    r = results["benchmarks"]
    r.append(bench("canonicalize/small", lambda: p.canonicalize(small, p.C14nMode.Inclusive)))
    r.append(bench("canonicalize/large", lambda: p.canonicalize(large, p.C14nMode.Inclusive), runs=10))
    r.append(bench("canonicalize_subtree/small", lambda: p.canonicalize_subtree(small, "_response", p.C14nMode.Exclusive)))
    r.append(bench("verify/hmac_small", lambda: p.verify(ctx, signed_small)))
    r.append(bench("verify/hmac_large", lambda: p.verify(ctx, signed_large), runs=10))
    r.append(bench("verify_all/hmac_small", lambda: p.verify_all(ctx, signed_small)))
    r.append(bench("sign_enveloped/hmac_small", lambda: p.sign_enveloped(ctx, small, signature_method=p.Algorithm.HMAC_SHA256)))
    r.append(bench("sign_enveloped/hmac_large", lambda: p.sign_enveloped(ctx, large, signature_method=p.Algorithm.HMAC_SHA256), runs=10))

    # Threaded wall-clock: if Rust work holds the GIL, 4 threads scale ~1x.
    def four_threads():
        with ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(lambda _: p.verify(ctx, signed_small), range(4)))

    t = bench("verify_small x4 threads (wall)", four_threads)
    r.append(t)
    single = next(b for b in r if b["name"] == "verify/hmac_small")
    results["build_info"]["thread_scaling"] = round(
        (4 * single["median_ms"]) / t["median_ms"], 2
    )

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print()
        print(f"thread scaling (4 workers, higher=better GIL release): "
              f"{results['build_info']['thread_scaling']}x")
    return 0


if __name__ == "__main__":
    sys.exit(main())
