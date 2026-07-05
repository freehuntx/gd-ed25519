#include "csprng.h"

#include <string.h>

// ---- Platform selection -----------------------------------------------------

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif
#else
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#if defined(__APPLE__)
#include <sys/random.h>
#endif
#endif

// ---- POSIX urandom fallback -----------------------------------------------
// Used when getentropy() is unavailable: ancient glibc (< 2.25) and Android
// before API 28 (Bionic only gained getentropy in Android 9). /dev/urandom
// is universally available on these targets and is seeded from the same
// kernel CSPRNG as getentropy/getrandom.

#if !defined(_WIN32)

// urandom_read is referenced when getentropy is unavailable at compile time
// (GD_USE_URANDOM) or as a runtime fallback on Linux. Compile it only on
// those targets to avoid -Wunused-function warnings on macOS/iOS/Emscripten.
#if (defined(__GLIBC__) && (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 25))) \
    || (defined(__ANDROID__) && __ANDROID_API__ < 28) \
    || defined(__linux__)
#define GD_HAS_URANDOM 1
#endif

#if (defined(__GLIBC__) && (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 25))) \
    || (defined(__ANDROID__) && __ANDROID_API__ < 28)
#define GD_USE_URANDOM 1
#endif

#if defined(GD_HAS_URANDOM)
static int urandom_read(uint8_t *out, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        return -1;
    }
    size_t got = 0;
    while (got < n)
    {
        ssize_t r = read(fd, out + got, n - got);
        if (r < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            close(fd);
            return -1;
        }
        if (r == 0)
        {
            close(fd);
            return -1;
        }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}
#endif // GD_HAS_URANDOM
#endif // ! _WIN32

// ---- Raw entropy (no self-test) --------------------------------------------

static int csprng_raw(uint8_t *out, size_t n)
{
    if (n == 0)
    {
        return 0;
    }

#if defined(_WIN32)
    NTSTATUS status = BCryptGenRandom(
        NULL, (PUCHAR)out, (ULONG)n,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return status == 0 ? 0 : -1;
#elif defined(GD_USE_URANDOM)
    // getentropy() unavailable (ancient glibc or Android < API 28).
    return urandom_read(out, n);
#else
    // getentropy() reads at most 256 bytes at a time (per POSIX).
    size_t off = 0;
    while (off < n)
    {
        size_t chunk = n - off;
        if (chunk > 256)
        {
            chunk = 256;
        }
        if (getentropy(out + off, chunk) != 0)
        {
#if defined(__linux__)
            // Last-resort fallback if getentropy() fails at runtime on Linux
            // (Android >= 28 included).
            return urandom_read(out, n);
#else
            return -1;
#endif
        }
        off += chunk;
    }
    return 0;
#endif
}

// ---- One-time self-test -----------------------------------------------------
//
// On the first call we draw 64 bytes (two 32-byte draws) and verify the
// source is not stuck (all-zero) and not repeating. A benign data race on
// the flag only causes the self-test to run an extra time, which is
// harmless. No weak fallback exists: failure is a hard error.
static int csprng_self_test_done = 0;

static int csprng_self_test(void)
{
    uint8_t a[32];
    uint8_t b[32];
    if (csprng_raw(a, 32) != 0)
    {
        return -1;
    }
    if (csprng_raw(b, 32) != 0)
    {
        return -1;
    }
    uint8_t acc_a = 0, acc_b = 0;
    for (int i = 0; i < 32; i++)
    {
        acc_a |= a[i];
        acc_b |= b[i];
    }
    if (acc_a == 0 || acc_b == 0)
    {
        return -1;
    }
    if (memcmp(a, b, 32) == 0)
    {
        return -1;
    }
    return 0;
}

int csprng_bytes(uint8_t *out, size_t n)
{
    if (!csprng_self_test_done)
    {
        if (csprng_self_test() != 0)
        {
            // Honour the "out is wiped on failure" contract: the self-test
            // failed before we ever wrote to `out`, so zero it explicitly.
            if (n > 0)
            {
                memset(out, 0, n);
            }
            return -1;
        }
        csprng_self_test_done = 1;
    }
    int rc = csprng_raw(out, n);
    if (rc != 0 && n > 0)
    {
        memset(out, 0, n);
    }
    return rc;
}
