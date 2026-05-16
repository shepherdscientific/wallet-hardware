#ifndef PSBT_SIGNER_H
#define PSBT_SIGNER_H

#include "psbt.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PSBT_SIGN_OK          0
#define PSBT_SIGN_ERR_SE     -1
#define PSBT_SIGN_ERR_PARAM  -2
#define PSBT_SIGN_ERR_NO_KEY -3
#define PSBT_SIGN_ERR_SIGHASH -4

#define PSBT_TEMP_KEY_ID     0xF0

bool sighash_bip143(const psbt_t *psbt, uint32_t input_index,
                     uint32_t sighash_type, uint8_t hash_out[32]);

bool sighash_bip341(const psbt_t *psbt, uint32_t input_index,
                     uint8_t hash_out[32]);

int psbt_sign(psbt_t *psbt, const bool *selected);

#ifdef __cplusplus
}
#endif

#endif
