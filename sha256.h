#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_DIGEST_LENGTH 32

void sha256(const uint8_t *data, size_t len, uint8_t hash[SHA256_DIGEST_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif
