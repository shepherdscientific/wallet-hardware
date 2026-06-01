#ifndef BECH32_H
#define BECH32_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BECH32_MAX_ENCODED_LEN 128

bool bech32_encode(const char *hrp, int witver,
                   const uint8_t *witprog, size_t witprog_len,
                   char out[BECH32_MAX_ENCODED_LEN]);

bool bech32m_encode(const char *hrp, int witver,
                    const uint8_t *witprog, size_t witprog_len,
                    char out[BECH32_MAX_ENCODED_LEN]);

#ifdef __cplusplus
}
#endif

#endif
