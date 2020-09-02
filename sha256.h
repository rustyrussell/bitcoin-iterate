#include <ccan/short_types/short_types.h>
#include <stddef.h>

typedef struct {
    u32 s[8];
    u32 buf[16]; /* In big endian */
    u64 bytes;
} sha256_context;

#define SHA256_DIGEST_LENGTH 32

void sha256_initialize(sha256_context* hash);
void sha256_write(sha256_context* hash, const u8* data, size_t size);
void sha256_finalize(sha256_context* hash, u8* out32);
