# Changelog

## [1.0.0](https://github.com/freehuntx/gd-ed25519/releases/tag/v1.0.0) - 2026-07-05

### Breaking changes

- **Ed25519 is now RFC 8032 compliant (SHA-512).** Previous versions used
  Monocypher's `crypto_eddsa_*` (BLAKE2b-EdDSA), which was _not_ interoperable
  with libsodium, WebCrypto or @noble/ed25519. Signatures produced by earlier
  versions will **not** verify with this release, and vice-versa. Re-sign any
  persisted data after upgrading, or keep both keys around during migration.
  (Vendored the optional `monocypher-ed25519.c/.h` which provides SHA-512
  Ed25519.)
- Legacy `Ed25519.encrypt`/`decrypt`: the Ed25519→X25519 scalar derivation now
  uses **SHA-512** (matching RFC 8032 / libsodium) instead of BLAKE2b. Blobs
  produced by previous versions are therefore **not** decryptable by this
  release.
- `Ed25519Keypair.from_private_key` now returns **`null`** (with an error) on an
  invalid key size, where it previously returned an _empty_ keypair. Code that
  probed validity via `.get_public_key().size()` must switch to a null check.
  (`from_private_key` is deprecated; use `from_seed`.)
- **`Ed25519.sign` now derives the public key from the seed internally and binds
  it to the seed.** This closes a key-extraction risk: signing the same seed
  with a mismatched public key yields two signatures that share `r` but differ
  in `h`, from which the private scalar can be recovered. The `public_key`
  argument is kept for source compatibility: pass an empty array to have it
  derived, or pass the 32-byte public key to have it checked - a mismatch now
  fails fast (empty signature + error) rather than silently producing a
  signature. The signature output is unchanged for callers that pass the
  correct public key or an empty one.

### Added

- **`Ed25519Keypair.from_seed(seed)` / `get_seed()`** - canonical seed API for
  deterministic keypair reconstruction. Accepts 32-byte seeds or 64-byte
  libsodium secret keys (first 32 bytes = seed).
- **`X25519` class + `X25519Keypair`** - pure RFC 7748 ephemeral keypair
  generation and raw Diffie-Hellman with constant-time all-zero (low-order
  point) detection. No Ed25519↔X25519 conversion is exposed.
- **`Monocypher` class** - symmetric primitives:
  - `aead_encrypt` / `aead_decrypt` - XChaCha20-Poly1305 AEAD, interoperable
    with libsodium `crypto_aead_xchacha20poly1305_ietf` and @noble/ciphers.
    Backed directly by Monocypher's `crypto_aead_lock`/`crypto_aead_unlock`
    (whose 24-byte-nonce djb counter layout is bit-identical to the IETF
    construction: `crypto_chacha20_ietf` is a thin wrapper around
    `crypto_chacha20_djb`). Verified against draft-irtf-cfrg-xchacha A.3.
    Failure returns `null` (distinct from an empty-plaintext success).
  - `blake2b(data, out_len = 32)` - unkeyed BLAKE2b, `1 ≤ out_len ≤ 64`.
- Dedicated CSPRNG helper (`src/csprng.c`): `getentropy()` / `BCryptGenRandom`,
  one-time self-test, hard-failure policy (no `RandomNumberGenerator` /
  `time`-based fallback anywhere). Replaces all previous entropy call sites.
- Headless test suite (`project/tests/test.gd`) with RFC/draft test vectors,
  wired into CI.
- Doc-class XML for all classes; README rewritten with a full API reference and
  a "which primitive for what" table.

### Vendored-library notes

- `src/monocypher.{c,h}` and `src/monocypher-ed25519.{c,h}` are vendored
  upstream Monocypher (BSD-2-Clause / CC0-1.0) with a single tiny local patch:
  one em-dash in a comment in `monocypher.c` (`extended_hash`) is replaced with
  an ASCII hyphen to avoid MSVC warning C4819 (source code not in the active
  codepage). The change is marked with a `[VENDOR-PATCH]` comment at the site.
  Keep this in mind when updating Monocypher from upstream.

### Deprecated

- `Ed25519Keypair.from_private_key` / `get_private_key` / `set_private_key` -
  kept as aliases for `from_seed` / `get_seed` / seed storage. New code should
  use the seed API.

### Security

- All randomness now comes from a CSPRNG with no weak fallbacks.
- Secrets are wiped on destruction and in temporaries on every return path.
- Legacy `Ed25519.encrypt`/`decrypt` retained for backward compatibility but
  documented as deprecated in favor of `X25519` handshake + `Monocypher` AEAD.

## [0.1.1](https://github.com/freehuntx/gd-ed25519/releases/tag/v0.1.1) - 2026-03-12

### Fixed

- **Added `.gitattributes`** - follows Godot assets best practices.

## [0.1.0](https://github.com/freehuntx/gd-ed25519/releases/tag/v0.1.0) - 2026-03-10

### Changed

- **Methods changed to static** - moved the `generate` function to accommodate
  static usage.

## [0.0.2](https://github.com/freehuntx/gd-ed25519/releases/tag/v0.0.2) - 2026-03-10

### Added

- **`from_private_key` initialization** - allows initializing from an existing
  private key.
- **Repository logo.**

## [0.0.1](https://github.com/freehuntx/gd-ed25519/releases/tag/v0.0.1) - 2026-03-04

### Added

- **Release branch logic.**
- **`LICENSE.md` file.**
- **Initial commit.**
