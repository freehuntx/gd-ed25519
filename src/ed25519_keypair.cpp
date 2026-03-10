#include "ed25519_keypair.h"
#include "monocypher.h"
#include <godot_cpp/core/class_db.hpp>

using namespace godot;

void Ed25519Keypair::_bind_methods()
{
  ClassDB::bind_static_method("Ed25519Keypair", D_METHOD("from_private_key", "private_key"), &Ed25519Keypair::from_private_key);

  ClassDB::bind_method(D_METHOD("set_public_key", "public_key"), &Ed25519Keypair::set_public_key);
  ClassDB::bind_method(D_METHOD("get_public_key"), &Ed25519Keypair::get_public_key);

  ClassDB::bind_method(D_METHOD("set_private_key", "private_key"), &Ed25519Keypair::set_private_key);
  ClassDB::bind_method(D_METHOD("get_private_key"), &Ed25519Keypair::get_private_key);

  ADD_PROPERTY(PropertyInfo(Variant::PACKED_BYTE_ARRAY, "public_key"), "set_public_key", "get_public_key");
  ADD_PROPERTY(PropertyInfo(Variant::PACKED_BYTE_ARRAY, "private_key"), "set_private_key", "get_private_key");
}

Ed25519Keypair::Ed25519Keypair()
{
}

Ed25519Keypair::~Ed25519Keypair()
{
  // Optionally wipe keys from memory, though PackedByteArray manages its own memory
  // and Godot doesn't provide easy secure wiping for variants.
}

Ref<Ed25519Keypair> Ed25519Keypair::from_private_key(const PackedByteArray &p_private_key)
{
  Ref<Ed25519Keypair> result;
  result.instantiate();

  if (p_private_key.size() != 32)
  {
    return result;
  }

  uint8_t seed_copy[32];
  for (int i = 0; i < 32; i++)
  {
    seed_copy[i] = p_private_key[i];
  }

  PackedByteArray public_key;
  public_key.resize(32);

  uint8_t secret_key[64];
  crypto_eddsa_key_pair(secret_key, public_key.ptrw(), seed_copy);
  crypto_wipe(secret_key, 64);

  result->set_private_key(p_private_key);
  result->set_public_key(public_key);

  return result;
}

void Ed25519Keypair::set_private_key(const PackedByteArray &p_key)
{
  private_key = p_key;
}

PackedByteArray Ed25519Keypair::get_private_key() const
{
  return private_key;
}

void Ed25519Keypair::set_public_key(const PackedByteArray &p_key)
{
  public_key = p_key;
}

PackedByteArray Ed25519Keypair::get_public_key() const
{
  return public_key;
}
