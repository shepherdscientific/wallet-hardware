#ifndef WALLET_STORAGE_H
#define WALLET_STORAGE_H

#include "bip39.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool wallet_generate_seed(const char mnemonic[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN],
                          const char *passphrase);

bool wallet_is_initialized(void);

#ifdef __cplusplus
}
#endif

#endif
