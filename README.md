# Ed25519 GDExtension for Godot 4

A GDExtension for Godot 4 that brings high-performance, secure cryptographic
primitives to the engine, backed by the lightweight
[Monocypher](https://monocypher.org/) library (vendored). It is designed to
serve as a thin, generic crypto backend.

## Features

- **Ed25519 signatures** (RFC 8032, SHA-512) - interoperable with libsodium,
  WebCrypto, @noble/ed25519.
- **Deterministic keypair reconstruction** from a stored 32-byte seed.
- **Pure X25519** (RFC 7748): ephemeral keypair generation + raw Diffie-Hellman.
- **XChaCha20-Poly1305 AEAD** (libsodium / @noble/ciphers compatible) with
  caller-supplied key/nonce/associated data.
- **BLAKE2b** with selectable output length (used as a KDF/hash).
- A legacy **Ed25519 → X25519 authenticated public-key encryption** API
  (`Ed25519.encrypt`/`decrypt`) kept for backward compatibility.
- Cross-platform: Linux, Windows, macOS, Android, iOS and **Web (WASM)**.
- All randomness comes from a CSPRNG with a hard-failure policy (no weak
  fallbacks); secrets are wiped on destruction and in temporaries.

## Registered classes

`Ed25519`, `Ed25519Keypair`, `X25519`, `X25519Keypair`, `Monocypher`.

## Which primitive for what?

| Need                                                    | Use                                                    |
| ------------------------------------------------------- | ------------------------------------------------------ |
| Sign a message (interop with libsodium/WebCrypto)       | `Ed25519.sign` / `Ed25519.verify`                      |
| Generate / persist an Ed25519 identity                  | `Ed25519Keypair.generate` / `.from_seed` / `.get_seed` |
| Ephemeral key agreement (handshake)                     | `X25519.generate_keypair` + `X25519.shared_secret`     |
| Authenticated encryption of a message                   | `Monocypher.aead_encrypt` / `.aead_decrypt`            |
| Derive a key / hash                                     | `Monocypher.blake2b`                                   |
| One-shot encrypt to a known Ed25519 public key (legacy) | `Ed25519.encrypt` / `.decrypt`                         |

> **Signature interoperability:** signatures produced by this addon are **RFC
> 8032 Ed25519** (SHA-512). Earlier versions used Monocypher's BLAKE2b-EdDSA,
> which was _not_ interoperable; that has been fixed. See the changelog for the
> breaking change.

## Installation

### Using precompiled binaries

1. Download the latest release from the Releases page.
2. Extract the archive and copy the `addons/ed25519` folder into your Godot
   project's `addons/` directory.
3. Open your Godot project - the extension loads automatically.

### Building from source

Prerequisites: [Godot 4](https://godotengine.org/), [SCons](https://scons.org/),
a C/C++ compiler (GCC, Clang, or MSVC). The `godot-cpp` submodule is required:
`git submodule update --init --recursive`.

```bash
# Linux
scons platform=linux arch=x86_64 target=template_debug
# Windows
scons platform=windows arch=x86_64 target=template_debug
# macOS
scons platform=macos arch=universal target=template_debug
# Web (WASM)
scons platform=web arch=wasm32 target=template_debug
```

Compiled libraries land in `project/addons/ed25519/<platform>/`.

## API reference (GDScript)

Once installed, all classes are registered globally.

### Ed25519 - signatures + legacy APKE

```gdscript
# Sign / verify (RFC 8032)
var kp := Ed25519Keypair.generate()
var msg := "hello".to_utf8_buffer()
var sig := Ed25519.sign(msg, kp.get_seed(), kp.get_public_key())
assert(Ed25519.verify(sig, msg, kp.get_public_key()))

# Persist & restore a keypair from its seed
var seed := kp.get_seed()
var restored := Ed25519Keypair.from_seed(seed)
assert(restored.get_public_key() == kp.get_public_key())

# libsodium-format import (64-byte seed||public_key) is also accepted
var libsk := kp.get_seed() + kp.get_public_key()
var k2 := Ed25519Keypair.from_seed(libsk)
```

`Ed25519.sign(message, private_key, public_key) -> PackedByteArray` -
`private_key` is the 32-byte seed. `public_key` is optional: pass an empty
array to have it derived from the seed, or pass the 32-byte public key to have
it checked (a mismatch fails fast). Returns a 64-byte signature, or an empty
array (with an error) on bad key sizes or a mismatched public key.

`Ed25519.verify(signature, message, public_key) -> bool`.

`Ed25519.encrypt(message, their_public_key, my_private_key) -> PackedByteArray`
and
`Ed25519.decrypt(encrypted_data, their_public_key, my_private_key) -> PackedByteArray`

- **legacy** Ed25519→X25519 authenticated public-key encryption. The blob is
  `nonce(24) || mac(16) || ciphertext`. New code should prefer a `X25519`
  handshake + `Monocypher` AEAD.

### Ed25519Keypair

- `static Ed25519Keypair generate()` - fresh keypair; null on CSPRNG failure.
- `static Ed25519Keypair from_seed(seed)` - 32 B (or 64 B libsodium secret-key
  import, first 32 B taken as seed); null + error otherwise.
- `PackedByteArray get_seed()` - 32-byte seed.
- `PackedByteArray get_public_key()` - 32-byte public key.
- `from_private_key` / `get_private_key` / `set_private_key` - **deprecated**
  aliases operating on the seed.

> **"private key" terminology:** this addon treats the 32-byte **seed** as the
> canonical private key. libsodium & others call the 64-byte
> `seed || public_key` value the "secret key". `from_seed` accepts both forms.

### X25519 - pure ephemeral key agreement

```gdscript
var alice := X25519.generate_keypair()
var bob   := X25519.generate_keypair()
var ss := X25519.shared_secret(alice.get_private_key(), bob.get_public_key())
assert(ss == X25519.shared_secret(bob.get_private_key(), alice.get_public_key()))
# ss is RAW - do not use it directly as a cipher key. KDF it:
var key := Monocypher.blake2b(ss + "handshake".to_utf8_buffer())
```

- `static X25519Keypair generate_keypair()`.
- `static Variant shared_secret(own_private, their_public)` - raw RFC 7748 DH.
  Returns the 32-byte shared secret, or null if the result is all-zero
  (low-order point - abort) or inputs aren't 32 bytes. **Do not** use the raw
  secret directly as a cipher key; run it through a KDF.

`X25519Keypair.get_private_key()` / `.get_public_key()` - 32 bytes each.

### Monocypher - symmetric primitives

```gdscript
var key   := Monocypher.blake2b("domain-separation".to_utf8_buffer())  # 32 bytes
var nonce := PackedByteArray(); nonce.resize(24)                       # 24-byte nonce; caller manages
var ad    := "context".to_utf8_buffer()
var ct    := Monocypher.aead_encrypt(key, nonce, plaintext, ad)
# ct == ciphertext || tag(16)

var pt := Monocypher.aead_decrypt(key, nonce, ct, ad)
if pt == null:
    push_error("authentication failed / bad input")
elif (pt as PackedByteArray).size() == 0:
    print("valid empty plaintext")   # distinct from failure
else:
    print("plaintext: ", (pt as PackedByteArray))

# BLAKE2b
var h := Monocypher.blake2b(data)
var h64 := Monocypher.blake2b(data, 64)
```

- `static Variant aead_encrypt(key, nonce, plaintext, ad = [])` -
  XChaCha20-Poly1305 AEAD. `key`=32, `nonce`=24, `ad` optional. Returns
  `ciphertext || tag(16)`, or null on bad sizes.
- `static Variant aead_decrypt(key, nonce, ciphertext_with_tag, ad = [])` -
  returns plaintext (possibly empty `PackedByteArray`) on success, null on
  authentication failure / bad sizes. Empty plaintext is distinguishable from
  failure.
- `static Variant blake2b(data, out_len = 32)` - unkeyed BLAKE2b,
  `1 ≤ out_len ≤ 64`. Returns the digest, or null if `out_len` is out of range.

## Security notes

- **CSPRNG:** randomness comes from `getentropy()` (Linux, macOS, Emscripten,
  Android >= 9 / API 28 - Emscripten backs it with the Web Crypto API) or
  `BCryptGenRandom` (Windows). On ancient glibc (< 2.25) and Android < API 28
  (where `getentropy` is unavailable) it falls back to `/dev/urandom`. There is
  no weak fallback; a failure is a hard error. A one-time self-test checks the
  source is not stuck or repeating.
- **Secret wiping:** seeds and other secret buffers are wiped with
  `crypto_wipe()` on destruction and in all temporaries.
- **No Ed25519↔X25519 key conversion** is exposed to users; X25519 keys are
  always freshly generated.

## Tests

A headless test suite lives in `project/tests/test.gd` and is run via:

```bash
godot --headless -s res://tests/test.gd
```

It covers RFC 8032 §7.1 (TEST 1 & TEST 3), RFC 7748 §5.2 & §6.1,
draft-irtf-cfrg-xchacha A.3, RFC 7693 Appendix A, seed round-trip identity, AEAD
round-trips + single-bit-flip failures, and backward compatibility of the legacy
API. The CI workflow runs it after building.

## License

MIT (see `LICENSE.md`). Vendored Monocypher is dual-licensed BSD-2-Clause /
CC0-1.0.
