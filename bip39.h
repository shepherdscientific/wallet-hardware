#ifndef BIP39_H
#define BIP39_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BIP39_WORDLIST_SIZE  2048
#define BIP39_WORD_MAX_LEN   9
#define BIP39_MNEMONIC_WORDS 24
#define BIP39_ENTROPY_LEN    32
#define BIP39_CHECKSUM_LEN   (BIP39_ENTROPY_LEN + 1)

extern const char bip39_wordlist[BIP39_WORDLIST_SIZE][BIP39_WORD_MAX_LEN];

bool bip39_generate(char wordlist[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN]);

bool bip39_validate(const char wordlist[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN]);

uint16_t bip39_word_to_index(const char *word);

uint16_t bip39_find_prefix(const char *prefix, uint16_t *first_match);

uint8_t bip39_prefix_match(const char *prefix, uint16_t *indices, uint8_t max_results);

#ifdef __cplusplus
}
#endif

#endif
