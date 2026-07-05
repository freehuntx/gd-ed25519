#include "ed25519_keypair.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "csprng.h"
#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/variant/utility_functions.hpp>
#include <godot_cpp/variant/variant.hpp>
#include <string.h>

using namespace godot;

void Ed25519Keypair::_bind_methods()
{
  ClassDB::bind_static_method("Ed25519Keypair", D_METHOD("generate"), &Ed25519Keypair::generate);
  ClassDB::bind_static_method("Ed25519Keypair", D_METHOD("from_seed", "seed"), &Ed25519Keypair::from_seed);

  // Deprecated aliases.
  ClassDB::bind_static_method("Ed25519Keypair", D_METHOD("from_private_key", "private_key"), &Ed25519Keypair::from_private_key);

  ClassDB::bind_method(D_METHOD("get_seed"), &Ed25519Keypair::get_seed);
  ClassDB::bind_method(D_METHOD("get_public_key"), &Ed25519Keypair::get_public_key);
  ClassDB::bind_method(D_METHOD("set_public_key", "public_key"), &Ed25519Keypair::set_public_key);

  // Deprecated aliases.
  ClassDB::bind_method(D_METHOD("get_private_key"), &Ed25519Keypair::get_private_key);
  ClassDB::bind_method(D_METHOD("set_private_key", "private_key"), &Ed25519Keypair::set_private_key);

  ADD_PROPERTY(PropertyInfo(Variant::PACKED_BYTE_ARRAY, "public_key"), "set_public_key", "get_public_key");
  // The "private_key" property is a deprecated alias for "seed".
  ADD_PROPERTY(PropertyInfo(Variant::PACKED_BYTE_ARRAY, "private_key"), "set_private_key", "get_private_key");
}

Ed25519Keypair::Ed25519Keypair() {}

Ed25519Keypair::~Ed25519Keypair()
{
  _wipe();
}

void Ed25519Keypair::_wipe()
{
  if (seed.size() == 32)
  {
    crypto_wipe(seed.ptrw(), 32);
  }
  // Public key is not secret, but wipe for tidiness.
  if (public_key.size() == 32)
  {
    crypto_wipe(public_key.ptrw(), 32);
  }
}

Ref<Ed25519Keypair> Ed25519Keypair::generate()
{
  Ref<Ed25519Keypair> result;
  result.instantiate();

  uint8_t seed_bytes[32];
  if (csprng_bytes(seed_bytes, 32) != 0)
  {
    UtilityFunctions::push_error("Ed25519Keypair.generate: CSPRNG failure; refusing to generate a key");
    return Ref<Ed25519Keypair>();
  }

  // crypto_ed25519_key_pair securely wipes the input seed, so we give it a
  // copy and keep the original.
  uint8_t seed_copy[32];
  memcpy(seed_copy, seed_bytes, 32);

  uint8_t public_key_bytes[32];
  uint8_t secret_key[64]; // expanded secret; wiped immediately
  crypto_ed25519_key_pair(secret_key, public_key_bytes, seed_copy);
  crypto_wipe(secret_key, 64);
  crypto_wipe(seed_copy, 32);

  result->seed.resize(32);
  memcpy(result->seed.ptrw(), seed_bytes, 32);
  result->public_key.resize(32);
  memcpy(result->public_key.ptrw(), public_key_bytes, 32);

  crypto_wipe(seed_bytes, 32);
  crypto_wipe(public_key_bytes, 32);

  return result;
}

Ref<Ed25519Keypair> Ed25519Keypair::from_seed(const PackedByteArray &p_seed)
{
  if (p_seed.size() != 32 && p_seed.size() != 64)
  {
    UtilityFunctions::push_error("Ed25519Keypair.from_seed: seed must be 32 bytes (or 64 bytes for libsodium secret-key import), got ",
                                 p_seed.size());
    return Ref<Ed25519Keypair>();
  }

  Ref<Ed25519Keypair> result;
  result.instantiate();

  // Use the first 32 bytes as the seed (handles both 32- and 64-byte
  // inputs; for 64-byte libsodium format bytes 32..63 are the public key
  // and are ignored - we re-derive the public key for consistency).
  uint8_t seed_bytes[32];
  memcpy(seed_bytes, p_seed.ptr(), 32);

  uint8_t seed_copy[32];
  memcpy(seed_copy, seed_bytes, 32);

  uint8_t public_key_bytes[32];
  uint8_t secret_key[64];
  crypto_ed25519_key_pair(secret_key, public_key_bytes, seed_copy);
  crypto_wipe(secret_key, 64);
  crypto_wipe(seed_copy, 32);

  result->seed.resize(32);
  memcpy(result->seed.ptrw(), seed_bytes, 32);
  result->public_key.resize(32);
  memcpy(result->public_key.ptrw(), public_key_bytes, 32);

  crypto_wipe(seed_bytes, 32);
  crypto_wipe(public_key_bytes, 32);

  return result;
}

PackedByteArray Ed25519Keypair::get_seed() const
{
  return seed;
}

PackedByteArray Ed25519Keypair::get_public_key() const
{
  return public_key;
}

// --- Deprecated aliases ---

Ref<Ed25519Keypair> Ed25519Keypair::from_private_key(const PackedByteArray &p_private_key)
{
  // Warn once per process: callers that intentionally keep using the alias
  // shouldn't get spammed on every call, but a one-time nudge preserves
  // discoverability of the canonical from_seed() API.
  static bool warned = false;
  if (!warned)
  {
    UtilityFunctions::push_warning("Ed25519Keypair.from_private_key is deprecated; use from_seed() instead.");
    warned = true;
  }
  return from_seed(p_private_key);
}

PackedByteArray Ed25519Keypair::get_private_key() const
{
  // Deprecated alias for the seed.
  return seed;
}

void Ed25519Keypair::set_private_key(const PackedByteArray &p_key)
{
  // Deprecated alias for the seed. Re-derives the public key from the seed
  // so the property round-trips correctly (e.g. when Godot deserialises a
  // resource and sets public_key before private_key). Prefer from_seed().
  //
  // An empty input is treated as a silent "clear" rather than an error:
  // Godot invokes property setters with the default (empty) value while
  // loading/instantiating resources, so erroring here would spam the console
  // on every scene load. Only explicitly wrong (non-empty) sizes push an
  // error - via from_seed().
  if (p_key.size() == 0)
  {
    _wipe();
    seed.clear();
    public_key.clear();
    return;
  }

  Ref<Ed25519Keypair> tmp = from_seed(p_key);
  if (tmp.is_valid() && tmp->seed.size() == 32)
  {
    _wipe();
    seed = tmp->seed;
    public_key = tmp->public_key;
  }
  else
  {
    _wipe();
    seed.clear();
    public_key.clear();
  }
}

void Ed25519Keypair::set_public_key(const PackedByteArray &p_key)
{
  public_key = p_key;
}
