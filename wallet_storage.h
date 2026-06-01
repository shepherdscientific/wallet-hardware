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

bool wallet_has_passphrase(void);

bool wallet_set_passphrase_flag(bool has);

bool wallet_generate_anti_phish(void);

bool wallet_has_anti_phish(void);

bool wallet_get_anti_phish(char words[4][BIP39_WORD_MAX_LEN]);

// BIP32 account-level xpub (m/84'/0'/0') stored in NVS during wallet setup.
// Long enough for any base58check xpub (~111 chars) plus NUL.
#define XPUB_STR_LEN  120

// Persist xpub_str to NVS (called internally by wallet_generate_seed).
bool wallet_store_account_xpub(const char *xpub_str);

// Read the stored xpub from NVS into xpub_out.
// Returns false if no xpub has been stored (wallet not yet initialized).
bool wallet_get_account_xpub(char xpub_out[XPUB_STR_LEN]);

#ifdef __cplusplus
}
#endif

#endif
