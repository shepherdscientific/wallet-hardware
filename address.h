#ifndef ADDRESS_H
#define ADDRESS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ADDRESS_LEN 128

typedef enum {
  ADDRESS_P2PKH,
  ADDRESS_P2WPKH,
  ADDRESS_P2TR
} address_type_t;

bool address_generate(address_type_t type, uint32_t index,
                      char addr_out[MAX_ADDRESS_LEN]);

bool address_generate_with_path(address_type_t type, uint32_t change,
                                uint32_t index, char addr_out[MAX_ADDRESS_LEN]);

const char *address_type_name(address_type_t type);

#ifdef __cplusplus
}
#endif

#endif
