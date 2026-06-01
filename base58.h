#ifndef BASE58_H
#define BASE58_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BASE58_MAX_ENCODED_LEN 128

bool base58check_encode(uint8_t version, const uint8_t *payload, size_t payload_len,
                        char out[BASE58_MAX_ENCODED_LEN]);

#ifdef __cplusplus
}
#endif

#endif
