#ifndef ED25519_KEYPAIR_H
#define ED25519_KEYPAIR_H

#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/variant/packed_byte_array.hpp>

namespace godot
{

  class Ed25519Keypair : public RefCounted
  {
    GDCLASS(Ed25519Keypair, RefCounted)

  private:
    PackedByteArray private_key;
    PackedByteArray public_key;

  protected:
    static void _bind_methods();

  public:
    Ed25519Keypair();
    ~Ed25519Keypair();

    static Ref<Ed25519Keypair> generate();
    static Ref<Ed25519Keypair> from_private_key(const PackedByteArray &p_private_key);

    void set_private_key(const PackedByteArray &p_key);
    PackedByteArray get_private_key() const;

    void set_public_key(const PackedByteArray &p_key);
    PackedByteArray get_public_key() const;
  };

} // namespace godot

#endif // ED25519_KEYPAIR_H
