#ifndef BASE64_H
#define BASE64_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t base64_encode(const uint8_t *data, size_t len, char *out, size_t out_max);

size_t base64_decode(const char *in, size_t len, uint8_t *out, size_t out_max);

#ifdef __cplusplus
}
#endif

#endif
