#ifndef X25519_KEYPAIR_H
#define X25519_KEYPAIR_H

#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/variant/packed_byte_array.hpp>

namespace godot
{

  // A pure X25519 (Curve25519) keypair. Independent from Ed25519 keys;
  // this addon never converts between the two. Intended for ephemeral
  // Diffie-Hellman key agreement.
  class X25519Keypair : public RefCounted
  {
    GDCLASS(X25519Keypair, RefCounted)

  private:
    PackedByteArray private_key; // 32-byte X25519 secret scalar (before clamping)
    PackedByteArray public_key;  // 32-byte X25519 public key

    void _wipe();
    // NOTE: PackedByteArray is copy-on-write, so crypto_wipe on ptrw() only
    // wipes the COW-detached copy, not the underlying storage held by other
    // references. Real secret wiping therefore happens on the raw uint8_t
    // stack buffers in X25519::generate_keypair(), not on PackedByteArrays.

  protected:
    static void _bind_methods();

  public:
    X25519Keypair();
    ~X25519Keypair();

    PackedByteArray get_private_key() const;
    PackedByteArray get_public_key() const;

    // For internal construction by X25519::generate_keypair().
    void _assign(const PackedByteArray &p_private, const PackedByteArray &p_public);
  };

} // namespace godot

#endif // X25519_KEYPAIR_H
