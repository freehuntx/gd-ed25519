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
    // The 32-byte Ed25519 seed. This is the canonical private key
    // representation for this addon (see get_seed()). The internal 64-byte
    // expanded secret is derived from it on demand and never stored.
    PackedByteArray seed;
    PackedByteArray public_key;

    void _wipe();
    // NOTE: PackedByteArray is copy-on-write, so crypto_wipe on ptrw() only
    // wipes the COW-detached copy, not the underlying storage held by other
    // references. The destructor wipe is therefore best-effort. The genuinely
    // secret buffers (raw uint8_t[32]/[64] on the stack in generate() and
    // from_seed()) are wiped directly.

  protected:
    static void _bind_methods();

  public:
    Ed25519Keypair();
    ~Ed25519Keypair();

    // Canonical seed API. `seed` must be exactly 32 bytes, OR 64 bytes
    // (libsodium secret-key import: the first 32 bytes are taken as the
    // seed). Any other length returns null with an error.
    static Ref<Ed25519Keypair> from_seed(const PackedByteArray &p_seed);
    static Ref<Ed25519Keypair> generate();

    // Returns a copy of the 32-byte seed.
    PackedByteArray get_seed() const;

    // 32-byte public key.
    PackedByteArray get_public_key() const;

    // --- Deprecated aliases (kept for backward compatibility) ---
    // These all operate on the 32-byte seed. New code should use
    // from_seed() / get_seed().
    static Ref<Ed25519Keypair> from_private_key(const PackedByteArray &p_private_key);
    PackedByteArray get_private_key() const;
    void set_private_key(const PackedByteArray &p_key);

    void set_public_key(const PackedByteArray &p_key);
  };

} // namespace godot

#endif // ED25519_KEYPAIR_H
