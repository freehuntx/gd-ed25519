#include "ed25519.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "csprng.h"

#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/variant/utility_functions.hpp>
#include <godot_cpp/variant/variant.hpp>
#include <string.h>

using namespace godot;

void Ed25519::_bind_methods()
{
  ClassDB::bind_static_method("Ed25519", D_METHOD("sign", "message", "private_key", "public_key"), &Ed25519::sign);
  ClassDB::bind_static_method("Ed25519", D_METHOD("verify", "signature", "message", "public_key"), &Ed25519::verify);
  ClassDB::bind_static_method("Ed25519", D_METHOD("encrypt", "message", "their_public_key", "my_private_key"), &Ed25519::encrypt);
  ClassDB::bind_static_method("Ed25519", D_METHOD("decrypt", "encrypted_data", "their_public_key", "my_private_key"), &Ed25519::decrypt);
}

Ed25519::Ed25519() {}

Ed25519::~Ed25519() {}

// Note on the "private_key" argument: this addon treats the 32-byte Ed25519
// seed as the canonical private key (see Ed25519Keypair.get_seed()).
//
// The public key is bound to the seed: it is derived internally via
// crypto_ed25519_key_pair rather than trusted from the caller. This closes a
// key-extraction attack - if the same seed were signed with two different
// public keys, the resulting signatures would share `r` (which depends only on
// the seed prefix) but differ in `h`, from which the private scalar can be
// recovered. This matters precisely because this library is generic and does
// not control its callers.
//
// The `public_key` argument is accepted for source compatibility and treated
// as follows:
//   - empty  -> derive the public key from the seed (canonical path).
//   - 32 bytes that match the derived key -> proceed.
//   - 32 bytes that do NOT match -> push_error + empty signature. A mismatched
//     public key is a caller bug and we fail fast rather than mask it. (This
//     also rejects the attack form: an attacker who supplies a wrong public key
//     gets no second signature at all.)
// Any other size is rejected as before.
PackedByteArray Ed25519::sign(const PackedByteArray &message, const PackedByteArray &private_key, const PackedByteArray &public_key)
{
  PackedByteArray signature;

  if (private_key.size() != 32)
  {
    UtilityFunctions::push_error("Ed25519.sign: private_key (seed) must be 32 bytes (got ",
                                 private_key.size(), ")");
    return signature;
  }
  if (public_key.size() != 0 && public_key.size() != 32)
  {
    UtilityFunctions::push_error("Ed25519.sign: public_key must be empty (derive) or 32 bytes (got ",
                                 public_key.size(), ")");
    return signature;
  }

  // Derive the 64-byte expanded secret (seed || public_key) from the seed
  // alone. crypto_ed25519_key_pair securely wipes its input seed, so we hand
  // it a copy and keep the original seed as the first 32 bytes of secret_key.
  uint8_t seed_copy[32];
  memcpy(seed_copy, private_key.ptr(), 32);

  uint8_t secret_key[64];
  uint8_t derived_public_key[32];
  crypto_ed25519_key_pair(secret_key, derived_public_key, seed_copy);
  crypto_wipe(seed_copy, 32);

  // If a public key was supplied, it must match the one derived from the seed.
  if (public_key.size() == 32 &&
      crypto_verify32(public_key.ptr(), derived_public_key) != 0)
  {
    UtilityFunctions::push_error("Ed25519.sign: public_key does not match the key derived from the seed; refusing to sign (possible caller bug or key-extraction attempt)");
    crypto_wipe(secret_key, 64);
    crypto_wipe(derived_public_key, 32);
    return signature;
  }

  signature.resize(64);

  crypto_ed25519_sign(
      signature.ptrw(),
      secret_key,
      message.ptr(),
      message.size());

  crypto_wipe(secret_key, 64);
  crypto_wipe(derived_public_key, 32);

  return signature;
}

bool Ed25519::verify(const PackedByteArray &signature, const PackedByteArray &message, const PackedByteArray &public_key)
{
  // verify() validates untrusted input (network packets, etc.). A size
  // mismatch is not a programmer error but an expected adversarial case, so
  // stay silent and just return false rather than flooding the console.
  if (signature.size() != 64 || public_key.size() != 32)
  {
    return false;
  }

  int result = crypto_ed25519_check(
      signature.ptr(),
      public_key.ptr(),
      message.ptr(),
      message.size());

  return result == 0; // 0 means success in Monocypher
}

PackedByteArray Ed25519::encrypt(const PackedByteArray &message, const PackedByteArray &their_public_key, const PackedByteArray &my_private_key)
{
  PackedByteArray result;

  if (their_public_key.size() != 32 || my_private_key.size() != 32)
  {
    UtilityFunctions::push_error("Ed25519.encrypt: their_public_key and my_private_key must be 32 bytes each (got ",
                                 their_public_key.size(), " and ", my_private_key.size(), ")");
    return result;
  }

  // 1. Convert Ed25519 keys to X25519 keys (curve-point operations,
  //    hash-independent; valid on RFC 8032 public keys).
  uint8_t x25519_my_private_key[32];
  {
    uint8_t a[64];
    crypto_sha512(a, my_private_key.ptr(), 32);
    crypto_eddsa_trim_scalar(x25519_my_private_key, a);
    crypto_wipe(a, 64);
  }

  uint8_t x25519_their_public_key[32];
  crypto_eddsa_to_x25519(x25519_their_public_key, their_public_key.ptr());

  // 2. Perform X25519 key exchange to get shared secret
  uint8_t shared_secret[32];
  crypto_x25519(shared_secret, x25519_my_private_key, x25519_their_public_key);
  crypto_wipe(x25519_my_private_key, 32);

  // 3. Generate random nonce (24 bytes for XChaCha20-Poly1305) via CSPRNG.
  uint8_t nonce[24];
  if (csprng_bytes(nonce, 24) != 0)
  {
    UtilityFunctions::push_error("Ed25519.encrypt: CSPRNG failure; refusing to encrypt");
    crypto_wipe(shared_secret, 32);
    return result;
  }

  // 4. Encrypt using AEAD (XChaCha20-Poly1305, 24-byte nonce).
  PackedByteArray ciphertext;
  ciphertext.resize(message.size());

  uint8_t mac[16];

  crypto_aead_lock(
      ciphertext.ptrw(),
      mac,
      shared_secret,
      nonce,
      nullptr, // No additional data
      0,
      message.ptr(),
      message.size());

  // 5. Combine nonce + mac + ciphertext
  PackedByteArray nonce_pba;
  nonce_pba.resize(24);
  memcpy(nonce_pba.ptrw(), nonce, 24);

  PackedByteArray mac_pba;
  mac_pba.resize(16);
  memcpy(mac_pba.ptrw(), mac, 16);

  result.append_array(nonce_pba);
  result.append_array(mac_pba);
  result.append_array(ciphertext);

  crypto_wipe(shared_secret, 32);
  crypto_wipe(nonce, 24);
  crypto_wipe(mac, 16);

  return result;
}

PackedByteArray Ed25519::decrypt(const PackedByteArray &encrypted_data, const PackedByteArray &their_public_key, const PackedByteArray &my_private_key)
{
  PackedByteArray plaintext;

  if (their_public_key.size() != 32 || my_private_key.size() != 32)
  {
    UtilityFunctions::push_error("Ed25519.decrypt: their_public_key and my_private_key must be 32 bytes each (got ",
                                 their_public_key.size(), " and ", my_private_key.size(), ")");
    return plaintext;
  }

  // Minimum size: 24 (nonce) + 16 (mac) = 40 bytes
  if (encrypted_data.size() < 40)
  {
    UtilityFunctions::push_error("Ed25519.decrypt: encrypted_data must be at least 40 bytes (got ",
                                 encrypted_data.size(), ")");
    return plaintext;
  }

  // 1. Extract nonce, mac, and ciphertext
  const uint8_t *nonce_ptr = encrypted_data.ptr();
  const uint8_t *mac_ptr = encrypted_data.ptr() + 24;
  const uint8_t *ciphertext_ptr = encrypted_data.ptr() + 40;
  size_t ciphertext_size = encrypted_data.size() - 40;

  // 2. Convert Ed25519 keys to X25519 keys
  uint8_t x25519_my_private_key[32];
  {
    uint8_t a[64];
    crypto_sha512(a, my_private_key.ptr(), 32);
    crypto_eddsa_trim_scalar(x25519_my_private_key, a);
    crypto_wipe(a, 64);
  }

  uint8_t x25519_their_public_key[32];
  crypto_eddsa_to_x25519(x25519_their_public_key, their_public_key.ptr());

  // Perform X25519 key exchange to get shared secret
  uint8_t shared_secret[32];
  crypto_x25519(shared_secret, x25519_my_private_key, x25519_their_public_key);
  crypto_wipe(x25519_my_private_key, 32);

  // 3. Decrypt and verify
  plaintext.resize(ciphertext_size);

  int result = crypto_aead_unlock(
      plaintext.ptrw(),
      mac_ptr,
      shared_secret,
      nonce_ptr,
      nullptr, // No additional data
      0,
      ciphertext_ptr,
      ciphertext_size);

  crypto_wipe(shared_secret, 32);

  if (result != 0)
  {
    // Decryption or verification failed
    plaintext.clear();
  }

  return plaintext;
}
