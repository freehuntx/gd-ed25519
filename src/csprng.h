#ifndef GD_ED25519_CSPRNG_H
#define GD_ED25519_CSPRNG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Fills `out` with `n` cryptographically secure random bytes.
// Returns 0 on success, non-zero on failure.
// On failure `out` is wiped with zeros.
//
// Sources (in order of preference, selected at compile time):
//   Linux / macOS / Emscripten / Android (>= API 28): getentropy()
//       (Emscripten libc backs this with the Web Crypto API /
//       crypto.getRandomValues - no JS interop needed from the extension).
//   Windows: BCryptGenRandom.
//   Fallback (ancient glibc < 2.25, or Android < API 28 where getentropy is
//       unavailable): /dev/urandom.
//
// There is NO weak (rand/time-based) fallback. A failure here is a hard
// error: callers must abort the operation and report an error rather than
// proceed with a possibly predictable key.
int csprng_bytes(uint8_t *out, size_t n);

#ifdef __cplusplus
}
#endif

#endif // GD_ED25519_CSPRNG_H
