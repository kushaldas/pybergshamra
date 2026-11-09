# Dependency ecosystem status

Last reviewed: 2026-11-09. Versions were checked against crates.io with
`cargo outdated --depth 1` and Python dependencies refreshed with
`uv lock --upgrade`.

## Direct Rust dependencies

| Dependency | Manifest requirement | Latest stable |
| --- | --- | --- |
| All eight direct Bergshamra crates | 0.12.0 | 0.12.0 |
| Kryptering | 0.7.1 | 0.7.1 |
| PyO3 | 0.30.1 | 0.30.1 |
| base64 | 0.23.1 | 0.23.1 |
| Uppsala | 0.12.1 | 0.12.1 |

`cargo outdated --depth 1` reports all direct dependencies up to date.
There are no blocked direct dependency upgrades.

## Security and compatibility

Bergshamra 0.12.0 and Kryptering 0.7.1 both use RSA 0.10.0. This removes
RSA 0.9.10 and 0.10.0-rc.19, which were reported under RUSTSEC-2023-0071.
Bergshamra 0.11.2 still required RSA 0.9, so updating Kryptering alone was
insufficient to clear the audit.

The crypto dependency graph still includes multiple generations of some
RustCrypto trait crates through upstream dependencies. Those dependencies
remain under upstream version constraints; this package does not pin or
patch transitive trait crates independently.

PyO3 0.30.1 makes `skip_from_py_object` the default and deprecates the explicit
attribute. The six explicit attributes were removed. The extension retains
its Python 3.10 minimum and `abi3-py310` configuration.

## Lockfile refresh

In addition to the direct updates, compatible transitive updates include:

| Crate | Before | After |
| --- | --- | --- |
| tsp-ltv | 0.6.0 | 0.6.1 |
| crypto-bigint | 0.7.10 | 0.7.11 |
| ctutils | 0.4.6 | 0.4.8 |
| der (0.8 line) | 0.8.2 | 0.8.3 |
| elliptic-curve | 0.14.1 | 0.14.3 |
| inout (0.2 line) | 0.2.5 | 0.2.6 |
| ml-dsa | 0.1.1 | 0.1.2 |
| ml-kem | 0.3.2 | 0.3.4 |
| module-lattice | 0.2.3 | 0.2.4 |
| pkcs1 (0.8 line) | 0.8.0-rc.5 | 0.8.0 |
| yasna | 0.5.2 | 0.6.0 |

`uv.lock` also refreshes the development and documentation dependencies,
including pytest 9.2.0, pyuppsala 0.13.1, and Sphinx 9.2.0 on Python 3.14.
Python-version markers preserve resolution for older supported interpreters.

## Verification

Builds used a clean temporary copy of tracked project files, without the
checkout's untracked local Kryptering path override, to test published crates.

- `cargo build --all-features`: passed.
- `cargo test --all-features --lib`: passed (no Rust unit tests defined).
- `cargo clippy --all-features --all-targets -- -D warnings`: passed.
- `cargo fmt --check`: passed.
- `cargo audit --deny warnings`: passed, 227 locked crates checked.
- `cargo outdated --depth 1`: all direct dependencies up to date.
- `uv run --no-sync maturin develop`: built and installed the abi3 extension.
- Python tests on CPython 3.14.6, including provisioned SoftHSM2 integration:
  206 passed.
