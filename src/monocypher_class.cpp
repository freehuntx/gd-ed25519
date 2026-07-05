#include "monocypher_class.h"
#include "monocypher.h"
#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/variant/utility_functions.hpp>

using namespace godot;

void Monocypher::_bind_methods()
{
  ClassDB::bind_static_method("Monocypher", D_METHOD("aead_encrypt", "key", "nonce", "plaintext", "ad"),
                              &Monocypher::aead_encrypt, DEFVAL(PackedByteArray()));
  ClassDB::bind_static_method("Monocypher", D_METHOD("aead_decrypt", "key", "nonce", "ciphertext_with_tag", "ad"),
                              &Monocypher::aead_decrypt, DEFVAL(PackedByteArray()));
  ClassDB::bind_static_method("Monocypher", D_METHOD("blake2b", "data", "out_len"),
                              &Monocypher::blake2b, DEFVAL(32));
}

Monocypher::Monocypher() {}
Monocypher::~Monocypher() {}

// ---------------------------------------------------------------------------
// XChaCha20-Poly1305 AEAD (libsodium crypto_aead_xchacha20poly1305_ietf
// compatible)
// ---------------------------------------------------------------------------
//
// Monocypher's crypto_aead_lock() / crypto_aead_unlock() with a 24-byte nonce
// implement exactly the XChaCha20-Poly1305-IETF construction: HChaCha20 derives
// a subkey from key + nonce[0:16], then ChaCha20-Poly1305 runs with the djb
// counter layout (counter words 12-13, nonce words 14-15) at counter 0. The djb
// counter layout with a zero high counter word and the 8-byte nonce in words
// 14-15 is bit-identical to the IETF layout (32-bit counter in word 12, 96-bit
// nonce in words 13-15) with the IETF nonce = 0x00000000 || nonce[16:24].
// crypto_chacha20_ietf() in Monocypher is literally a wrapper around
// crypto_chacha20_djb() that confirms this. The Poly1305 MAC construction
// (lock_auth) matches RFC 8439 §2.8. Hence no hand-rolled composition is
// needed - we delegate to crypto_aead_lock/unlock directly. Verified against
// draft-irtf-cfrg-xchacha Appendix A.3 by the test suite.

Variant Monocypher::aead_encrypt(const PackedByteArray &key,
                                 const PackedByteArray &nonce,
                                 const PackedByteArray &plaintext,
                                 const PackedByteArray &ad)
{
  if (key.size() != 32)
  {
    UtilityFunctions::push_error("Monocypher.aead_encrypt: key must be 32 bytes (got ", key.size(), ")");
    return Variant();
  }
  if (nonce.size() != 24)
  {
    UtilityFunctions::push_error("Monocypher.aead_encrypt: nonce must be 24 bytes (got ", nonce.size(), ")");
    return Variant();
  }

  const uint8_t *ad_ptr = ad.size() > 0 ? ad.ptr() : nullptr;
  size_t ad_size = ad.size();

  // Output layout: ciphertext || tag(16).
  PackedByteArray out;
  out.resize(plaintext.size() + 16);

  crypto_aead_lock(
      out.ptrw(),                            // cipher_text
      out.ptrw() + plaintext.size(),         // mac (appended as tag)
      key.ptr(),
      nonce.ptr(),
      ad_ptr,
      ad_size,
      plaintext.ptr(),
      plaintext.size());

  return out;
}

Variant Monocypher::aead_decrypt(const PackedByteArray &key,
                                 const PackedByteArray &nonce,
                                 const PackedByteArray &ciphertext_with_tag,
                                 const PackedByteArray &ad)
{
  if (key.size() != 32)
  {
    UtilityFunctions::push_error("Monocypher.aead_decrypt: key must be 32 bytes (got ", key.size(), ")");
    return Variant();
  }
  if (nonce.size() != 24)
  {
    UtilityFunctions::push_error("Monocypher.aead_decrypt: nonce must be 24 bytes (got ", nonce.size(), ")");
    return Variant();
  }
  if (ciphertext_with_tag.size() < 16)
  {
    UtilityFunctions::push_error("Monocypher.aead_decrypt: ciphertext_with_tag must be at least 16 bytes (got ",
                                ciphertext_with_tag.size(), ")");
    return Variant();
  }

  const uint8_t *ad_ptr = ad.size() > 0 ? ad.ptr() : nullptr;
  size_t ad_size = ad.size();

  size_t cipher_size = ciphertext_with_tag.size() - 16;
  const uint8_t *mac_ptr = ciphertext_with_tag.ptr() + cipher_size;

  PackedByteArray plaintext;
  plaintext.resize(cipher_size);

  int result = crypto_aead_unlock(
      plaintext.ptrw(),
      mac_ptr,
      key.ptr(),
      nonce.ptr(),
      ad_ptr,
      ad_size,
      ciphertext_with_tag.ptr(),
      cipher_size);

  if (result != 0)
  {
    if (cipher_size > 0)
    {
      crypto_wipe(plaintext.ptrw(), cipher_size);
    }
    plaintext.clear();
    return Variant();
  }

  return plaintext;
}

Variant Monocypher::blake2b(const PackedByteArray &data, int out_len)
{
  if (out_len < 1 || out_len > 64)
  {
    UtilityFunctions::push_error("Monocypher.blake2b: out_len must be between 1 and 64 (got ", out_len, ")");
    return Variant();
  }

  PackedByteArray hash;
  hash.resize(out_len);

  crypto_blake2b(
      hash.ptrw(),
      (size_t)out_len,
      data.ptr(),
      data.size());

  return hash;
}
