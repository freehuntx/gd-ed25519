#include "ed25519_keypair.h"
#include <godot_cpp/core/class_db.hpp>

using namespace godot;

void Ed25519Keypair::_bind_methods()
{
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
