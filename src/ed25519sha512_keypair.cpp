//
// Created by shubertm on 4/19/26.
//

#include "ed25519sha512_keypair.h"
#include "monocypher-ed25519.h"

#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/classes/os.hpp>
#include <godot_cpp/classes/random_number_generator.hpp>

using namespace godot;

void Ed25519SHA512Keypair::_bind_methods()
{
  ClassDB::bind_static_method("Ed25519SHA512Keypair", D_METHOD("generate"), &Ed25519SHA512Keypair::generate);
  ClassDB::bind_static_method("Ed25519SHA512Keypair", D_METHOD("from_private_key", "private_key"), &Ed25519SHA512Keypair::from_private_key);

  ClassDB::bind_method(D_METHOD("set_public_key", "public_key"), &Ed25519SHA512Keypair::set_public_key);
  ClassDB::bind_method(D_METHOD("get_public_key"), &Ed25519SHA512Keypair::get_public_key);

  ClassDB::bind_method(D_METHOD("set_private_key", "private_key"), &Ed25519SHA512Keypair::set_private_key);
  ClassDB::bind_method(D_METHOD("get_private_key"), &Ed25519SHA512Keypair::get_private_key);

  ADD_PROPERTY(PropertyInfo(Variant::PACKED_BYTE_ARRAY, "public_key"), "set_public_key", "get_public_key");
  ADD_PROPERTY(PropertyInfo(Variant::PACKED_BYTE_ARRAY, "private_key"), "set_private_key", "get_private_key");
}

Ed25519SHA512Keypair::Ed25519SHA512Keypair()
{
}

Ed25519SHA512Keypair::~Ed25519SHA512Keypair()
{
  // Optionally wipe keys from memory, though PackedByteArray manages its own memory
  // and Godot doesn't provide easy secure wiping for variants.
}

Ref<Ed25519SHA512Keypair> Ed25519SHA512Keypair::generate()
{
  Ref<Ed25519SHA512Keypair> result;
  result.instantiate();

  // Generate 32 bytes of random data for the private key
  PackedByteArray private_key;
  private_key.resize(32);

  // Use Godot's OS class to get cryptographically secure random bytes if possible
  // For simplicity and cross-platform compatibility in this example, we'll use RandomNumberGenerator
  // In a production environment, you might want to use OS::get_singleton()->get_entropy() if available
  // or a dedicated CSPRNG.

  // Note: Godot 4.x OS::get_entropy is the proper way to get secure random bytes
  PackedByteArray entropy = OS::get_singleton()->get_entropy(32);
  if (entropy.size() == 32)
  {
    private_key = entropy;
  }
  else
  {
    // Fallback (not cryptographically secure, but prevents crashing if get_entropy fails)
    Ref<RandomNumberGenerator> rng;
    rng.instantiate();
    rng->randomize();
    for (int i = 0; i < 32; ++i)
    {
      private_key[i] = rng->randi() % 256;
    }
  }

  PackedByteArray public_key;
  public_key.resize(32);

  // crypto_eddsa_key_pair securely wipes the input seed, so we give it a copy
  uint8_t seed_copy[32];
  for (int i = 0; i < 32; i++)
  {
    seed_copy[i] = private_key[i];
  }

  uint8_t secret_key[64];
  crypto_ed25519_key_pair(secret_key, public_key.ptrw(), seed_copy);

  // Return the original 32-byte seed as the private key
  result->set_private_key(private_key);
  result->set_public_key(public_key);

  return result;
}

Ref<Ed25519SHA512Keypair> Ed25519SHA512Keypair::from_private_key(const PackedByteArray &p_private_key)
{
  Ref<Ed25519SHA512Keypair> result;
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
  crypto_ed25519_key_pair(secret_key, public_key.ptrw(), seed_copy);
  crypto_wipe(secret_key, 64);

  result->set_private_key(p_private_key);
  result->set_public_key(public_key);

  return result;
}

void Ed25519SHA512Keypair::set_private_key(const PackedByteArray &p_key)
{
  private_key = p_key;
}

PackedByteArray Ed25519SHA512Keypair::get_private_key() const
{
  return private_key;
}

void Ed25519SHA512Keypair::set_public_key(const PackedByteArray &p_key)
{
  public_key = p_key;
}

PackedByteArray Ed25519SHA512Keypair::get_public_key() const
{
  return public_key;
}
