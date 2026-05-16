#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA512_DIGEST_LENGTH 64

typedef struct {
  uint8_t opaque[256];
} sha512_ctx;

void sha512_init(sha512_ctx *ctx);
void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len);
void sha512_final(sha512_ctx *ctx, uint8_t hash[SHA512_DIGEST_LENGTH]);

void sha512(const uint8_t *data, size_t len, uint8_t hash[SHA512_DIGEST_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif
