#ifndef MONOCYPHER_CLASS_H
#define MONOCYPHER_CLASS_H

#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/variant/packed_byte_array.hpp>
#include <godot_cpp/variant/variant.hpp>

namespace godot
{

  // Keyless / symmetric primitives backed by Monocypher: XChaCha20-Poly1305
  // AEAD and BLAKE2b. Named "Monocypher" to describe provenance and avoid
  // colliding with Godot core's "Crypto" class.
  class Monocypher : public RefCounted
  {
    GDCLASS(Monocypher, RefCounted)

  protected:
    static void _bind_methods();

  public:
    Monocypher();
    ~Monocypher();

    // XChaCha20-Poly1305 AEAD.
    //   key    : 32 bytes
    //   nonce  : 24 bytes (XChaCha)
    //   ad     : optional associated data (may be empty)
    // Returns ciphertext || tag (16 bytes appended), or null on bad sizes.
    static Variant aead_encrypt(const PackedByteArray &key,
                                const PackedByteArray &nonce,
                                const PackedByteArray &plaintext,
                                const PackedByteArray &ad);

    // XChaCha20-Poly1305 AEAD decryption.
    //   ciphertext_with_tag : ciphertext with the 16-byte tag appended
    // Returns the plaintext (possibly an empty PackedByteArray) on success,
    // or null if authentication fails or input sizes are invalid. Callers
    // can distinguish "empty plaintext" (returns an empty array) from
    // "failure" (returns null).
    static Variant aead_decrypt(const PackedByteArray &key,
                                const PackedByteArray &nonce,
                                const PackedByteArray &ciphertext_with_tag,
                                const PackedByteArray &ad);

    // Unkeyed BLAKE2b.
    //   out_len : 1..64 (default 32)
    // Returns the digest, or null if out_len is out of range.
    static Variant blake2b(const PackedByteArray &data, int out_len = 32);
  };

} // namespace godot

#endif // MONOCYPHER_CLASS_H
