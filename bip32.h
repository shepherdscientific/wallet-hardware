#ifndef BIP32_H
#define BIP32_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HD_PATH_LEN      5
#define HD_HARDENED      0x80000000U
#define BIP32_KEY_LEN    32
#define BIP32_CHAIN_LEN  32
#define BIP32_PUBKEY_LEN 33

typedef struct {
  uint32_t path[HD_PATH_LEN];
} hd_path_t;

typedef enum {
  HD_PURPOSE_BIP44 = 44,
  HD_PURPOSE_BIP84 = 84,
  HD_PURPOSE_BIP86 = 86,
} hd_purpose_t;

bool hd_derive_master_from_seed(const uint8_t *seed, size_t seed_len,
                                uint8_t master_key[BIP32_KEY_LEN],
                                uint8_t chain_code[BIP32_CHAIN_LEN]);

bool hd_ckd_priv(const uint8_t parent_key[BIP32_KEY_LEN],
                 const uint8_t parent_chain[BIP32_CHAIN_LEN],
                 uint32_t index,
                 uint8_t child_key[BIP32_KEY_LEN],
                 uint8_t child_chain[BIP32_CHAIN_LEN]);

bool hd_ckd_pub(const uint8_t parent_pubkey[BIP32_PUBKEY_LEN],
                const uint8_t parent_chain[BIP32_CHAIN_LEN],
                uint32_t index,
                uint8_t child_pubkey[BIP32_PUBKEY_LEN],
                uint8_t child_chain[BIP32_CHAIN_LEN]);

bool hd_derive_pubkey(const hd_path_t *path, uint32_t index,
                      uint8_t pubkey_out[BIP32_PUBKEY_LEN]);

bool hd_public_derive_path(const uint8_t pubkey_in[BIP32_PUBKEY_LEN],
                           const uint8_t chain_in[BIP32_CHAIN_LEN],
                           uint32_t change, uint32_t addr_index,
                           uint8_t pubkey_out[BIP32_PUBKEY_LEN],
                           uint8_t chain_out[BIP32_CHAIN_LEN]);

bool hd_pubkey_from_priv(const uint8_t privkey[BIP32_KEY_LEN],
                         uint8_t pubkey_out[BIP32_PUBKEY_LEN]);

// Test helper: multiply two 256-bit values mod secp256k1 field prime
bool hd_ec_pubkey_tweak(const uint8_t pubkey[BIP32_PUBKEY_LEN],
                        const uint8_t tweak[32],
                        uint8_t xonly_out[32]);

bool hd_test_mod_mul(const uint8_t a[32], const uint8_t b[32],
                     uint8_t result[32]);

bool hd_test_mod_inv(const uint8_t a[32], uint8_t result[32]);

#ifdef __cplusplus
}
#endif

#endif
