#ifndef ed25519_H
#define ed25519_H

#include "ed25519_keypair.h"

#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/variant/dictionary.hpp>
#include <godot_cpp/variant/packed_byte_array.hpp>

namespace godot
{

  class Ed25519 : public RefCounted
  {
    GDCLASS(Ed25519, RefCounted)

  protected:
    static void _bind_methods();

  public:
    Ed25519();
    ~Ed25519();

    // Key Generation
    Ref<Ed25519Keypair> generate_keypair();

    // Ed25519 Signatures
    PackedByteArray sign(const PackedByteArray &message, const PackedByteArray &private_key, const PackedByteArray &public_key);
    bool verify(const PackedByteArray &signature, const PackedByteArray &message, const PackedByteArray &public_key);

    // X25519 Encryption (Authenticated Public-Key Encryption)
    PackedByteArray encrypt(const PackedByteArray &message, const PackedByteArray &their_public_key, const PackedByteArray &my_private_key);
    PackedByteArray decrypt(const PackedByteArray &encrypted_data, const PackedByteArray &their_public_key, const PackedByteArray &my_private_key);
  };

} // namespace godot

#endif // ed25519_H
