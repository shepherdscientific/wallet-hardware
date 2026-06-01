#ifndef RIPEMD160_H
#define RIPEMD160_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIPEMD160_DIGEST_LENGTH 20
#define RIPEMD160_BLOCK_SIZE    64

typedef struct {
  uint8_t opaque[120];
} ripemd160_ctx;

void ripemd160_init(ripemd160_ctx *ctx);
void ripemd160_update(ripemd160_ctx *ctx, const uint8_t *data, size_t len);
void ripemd160_final(ripemd160_ctx *ctx, uint8_t hash[RIPEMD160_DIGEST_LENGTH]);

void ripemd160(const uint8_t *data, size_t len, uint8_t hash[RIPEMD160_DIGEST_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif
