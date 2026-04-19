#include "ed25519sha512.h"
#include "monocypher-ed25519.h"

#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/classes/os.hpp>
#include <godot_cpp/classes/random_number_generator.hpp>

using namespace godot;

void Ed25519SHA512::_bind_methods()
{
  ClassDB::bind_static_method("Ed25519SHA512", D_METHOD("sign", "message", "private_key", "public_key"), &Ed25519SHA512::sign);
  ClassDB::bind_static_method("Ed25519SHA512", D_METHOD("verify", "signature", "message", "public_key"), &Ed25519SHA512::verify);
  ClassDB::bind_static_method("Ed25519SHA512", D_METHOD("encrypt", "message", "their_public_key", "my_private_key"), &Ed25519SHA512::encrypt);
  ClassDB::bind_static_method("Ed25519SHA512", D_METHOD("decrypt", "encrypted_data", "their_public_key", "my_private_key"), &Ed25519SHA512::decrypt);
}

Ed25519SHA512::Ed25519SHA512() {}

Ed25519SHA512::~Ed25519SHA512() {}

PackedByteArray Ed25519SHA512::sign(const PackedByteArray &message, const PackedByteArray &private_key, const PackedByteArray &public_key)
{
  PackedByteArray signature;

  if (private_key.size() != 32 || public_key.size() != 32)
  {
    // Invalid key sizes
    return signature;
  }

  uint8_t secret_key[64];
  // Reconstruct the 64-byte secret key from the 32-byte seed and 32-byte public key
  for (int i = 0; i < 32; i++)
  {
    secret_key[i] = private_key[i];
    secret_key[i + 32] = public_key[i];
  }

  signature.resize(64);

  crypto_ed25519_sign(
      signature.ptrw(),
      secret_key,
      message.ptr(),
      message.size());

  crypto_wipe(secret_key, 64);

  return signature;
}

bool Ed25519SHA512::verify(const PackedByteArray &signature, const PackedByteArray &message, const PackedByteArray &public_key)
{
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

PackedByteArray Ed25519SHA512::encrypt(const PackedByteArray &message, const PackedByteArray &their_public_key, const PackedByteArray &my_private_key)
{
  PackedByteArray result;

  if (their_public_key.size() != 32 || my_private_key.size() != 32)
  {
    return result;
  }

  // 1. Convert Ed25519 keys to X25519 keys
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

  // 2. Generate random nonce (24 bytes for XChaCha20)
  PackedByteArray nonce = OS::get_singleton()->get_entropy(24);
  if (nonce.size() != 24)
  {
    // Fallback
    nonce.resize(24);
    Ref<RandomNumberGenerator> rng;
    rng.instantiate();
    rng->randomize();
    for (int i = 0; i < 24; ++i)
    {
      nonce[i] = rng->randi() % 256;
    }
  }

  // 3. Encrypt using AEAD (XChaCha20-Poly1305)
  PackedByteArray ciphertext;
  ciphertext.resize(message.size());

  PackedByteArray mac;
  mac.resize(16);

  crypto_aead_lock(
      ciphertext.ptrw(),
      mac.ptrw(),
      shared_secret,
      nonce.ptr(),
      nullptr, // No additional data
      0,
      message.ptr(),
      message.size());

  // 4. Combine nonce + mac + ciphertext
  result.append_array(nonce);
  result.append_array(mac);
  result.append_array(ciphertext);

  // Clear shared secret from memory
  crypto_wipe(shared_secret, 32);

  return result;
}

PackedByteArray Ed25519SHA512::decrypt(const PackedByteArray &encrypted_data, const PackedByteArray &their_public_key, const PackedByteArray &my_private_key)
{
  PackedByteArray plaintext;

  if (their_public_key.size() != 32 || my_private_key.size() != 32)
  {
    return plaintext;
  }

  // Minimum size: 24 (nonce) + 16 (mac) = 40 bytes
  if (encrypted_data.size() < 40)
  {
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

  // Clear shared secret from memory
  crypto_wipe(shared_secret, 32);

  if (result != 0)
  {
    // Decryption or verification failed
    plaintext.clear();
  }

  return plaintext;
}

