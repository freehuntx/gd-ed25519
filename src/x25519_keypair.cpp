#include "x25519_keypair.h"
#include "monocypher.h"
#include <godot_cpp/core/class_db.hpp>
#include <string.h>

using namespace godot;

void X25519Keypair::_bind_methods()
{
  ClassDB::bind_method(D_METHOD("get_private_key"), &X25519Keypair::get_private_key);
  ClassDB::bind_method(D_METHOD("get_public_key"), &X25519Keypair::get_public_key);
}

X25519Keypair::X25519Keypair() {}

X25519Keypair::~X25519Keypair()
{
  _wipe();
}

void X25519Keypair::_wipe()
{
  if (private_key.size() == 32)
  {
    crypto_wipe(private_key.ptrw(), 32);
  }
}

PackedByteArray X25519Keypair::get_private_key() const
{
  return private_key;
}

PackedByteArray X25519Keypair::get_public_key() const
{
  return public_key;
}

void X25519Keypair::_assign(const PackedByteArray &p_private, const PackedByteArray &p_public)
{
  _wipe();
  private_key = p_private;
  public_key = p_public;
}
