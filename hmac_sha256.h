#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HMAC_SHA256_BLOCK_SIZE 64
#define HMAC_SHA256_OUTPUT_SIZE 32

void cc_hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t mac[HMAC_SHA256_OUTPUT_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
