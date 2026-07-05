#include "x25519.h"
#include "monocypher.h"
#include "csprng.h"
#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/variant/utility_functions.hpp>
#include <string.h>

using namespace godot;

void X25519::_bind_methods()
{
  ClassDB::bind_static_method("X25519", D_METHOD("generate_keypair"), &X25519::generate_keypair);
  ClassDB::bind_static_method("X25519", D_METHOD("shared_secret", "own_private", "their_public"), &X25519::shared_secret);
}

X25519::X25519() {}
X25519::~X25519() {}

Ref<X25519Keypair> X25519::generate_keypair()
{
  uint8_t sk[32];
  if (csprng_bytes(sk, 32) != 0)
  {
    UtilityFunctions::push_error("X25519.generate_keypair: CSPRNG failure; refusing to generate a key");
    return Ref<X25519Keypair>();
  }

  uint8_t pk[32];
  crypto_x25519_public_key(pk, sk);

  Ref<X25519Keypair> kp;
  kp.instantiate();

  PackedByteArray priv;
  priv.resize(32);
  memcpy(priv.ptrw(), sk, 32);

  PackedByteArray pub;
  pub.resize(32);
  memcpy(pub.ptrw(), pk, 32);

  kp->_assign(priv, pub);

  crypto_wipe(sk, 32);
  crypto_wipe(pk, 32);

  return kp;
}

Variant X25519::shared_secret(const PackedByteArray &own_private, const PackedByteArray &their_public)
{
  if (own_private.size() != 32 || their_public.size() != 32)
  {
    UtilityFunctions::push_error("X25519.shared_secret: own_private and their_public must be 32 bytes each (got ",
                                 own_private.size(), " and ", their_public.size(), ")");
    return Variant();
  }

  uint8_t shared[32];
  crypto_x25519(shared, own_private.ptr(), their_public.ptr());

  // Constant-time all-zero check (low-order point → abort).
  uint8_t acc = 0;
  for (int i = 0; i < 32; i++)
  {
    acc |= shared[i];
  }

  if (acc == 0)
  {
    crypto_wipe(shared, 32);
    UtilityFunctions::push_error("X25519.shared_secret: all-zero shared secret (low-order point); aborting");
    return Variant();
  }

  PackedByteArray out;
  out.resize(32);
  memcpy(out.ptrw(), shared, 32);

  crypto_wipe(shared, 32);

  return out;
}
