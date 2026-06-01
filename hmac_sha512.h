#ifndef HMAC_SHA512_H
#define HMAC_SHA512_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HMAC_SHA512_BLOCK_SIZE 128
#define HMAC_SHA512_OUTPUT_SIZE 64

void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t mac[HMAC_SHA512_OUTPUT_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
