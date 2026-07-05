#ifndef X25519_H
#define X25519_H

#include "x25519_keypair.h"

#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/variant/packed_byte_array.hpp>
#include <godot_cpp/variant/variant.hpp>

namespace godot
{

  // Pure X25519 (RFC 7748) primitives: ephemeral keypair generation and
  // raw Diffie-Hellman. These keys are NOT Ed25519 keys and are never
  // converted to/from Ed25519 by this addon.
  class X25519 : public RefCounted
  {
    GDCLASS(X25519, RefCounted)

  protected:
    static void _bind_methods();

  public:
    X25519();
    ~X25519();

    // Generates a fresh ephemeral X25519 keypair. The private key is 32
    // random bytes (clamping is performed inside crypto_x25519_*).
    static Ref<X25519Keypair> generate_keypair();

    // Raw RFC 7748 Diffie-Hellman via crypto_x25519(shared, sk, pk).
    // Returns the 32-byte shared secret, or null if the result is all-zero
    // (low-order point; the zero check is performed in constant time).
    //
    // The returned secret is RAW and unhashed. Do NOT use it directly as a
    // cipher key - feed it through a KDF (e.g. Monocypher.blake2b with a
    // domain-separation string) at the protocol layer.
    static Variant shared_secret(const PackedByteArray &own_private, const PackedByteArray &their_public);
  };

} // namespace godot

#endif // X25519_H
