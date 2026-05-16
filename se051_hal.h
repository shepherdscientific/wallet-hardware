#ifndef SE051_HAL_H
#define SE051_HAL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ─── Compile-time HAL selection ───────────────────────────────────────────
#if defined(USE_SE051)
  #define SE051_HAL_ACTIVE 1
#elif defined(USE_SE_STUB)
  #define SE051_HAL_ACTIVE 1
#else
  #error "Define either USE_SE051 or USE_SE_STUB build flag"
#endif

// ─── I2C Constants ───────────────────────────────────────────────────────
#define SE051_I2C_ADDR        0x48
#define SE051_I2C_RETRY_COUNT 3
#define SE051_I2C_RETRY_MS    50

// ─── Key Object IDs ──────────────────────────────────────────────────────
#define SE051_KEY_BIP32_MASTER  0x01
#define SE051_KEY_CHAIN_CODE    0x02
#define SE051_OBJ_PIN_HASH      0x03
#define SE051_OBJ_ANTI_PHISH    0x04
#define SE051_OBJ_PIN_COUNTER   0x05
#define SE051_OBJ_FW_HASH          0x06
#define SE051_OBJ_HAS_PASSPHRASE  0x07

// ─── Buffer sizes ────────────────────────────────────────────────────────
#define SE051_RANDOM_LEN         32
#define SE051_HASH_LEN           32
#define SE051_PUBKEY_COMPRESSED  33
#define SE051_SCHNORR_SIG_LEN    64
#define SE051_ECDSA_MAX_DER_LEN  72

// ─── Typed Error Codes ───────────────────────────────────────────────────
typedef enum {
  SE_OK          = 0x00,
  SE_ERR_COMM    = 0x01,
  SE_ERR_AUTH    = 0x02,
  SE_ERR_LOCKED  = 0x03,
  SE_ERR_PARAM   = 0x04,
  SE_ERR_NOTFOUND = 0x05,
  SE_ERR_MEMORY  = 0x06,
  SE_ERR_INTERNAL = 0x7F
} se051_err_t;

// ─── Public HAL Functions ────────────────────────────────────────────────

se051_err_t se051_init(void);

se051_err_t se051_get_random(uint8_t *buf, size_t len);

se051_err_t se051_ecdsa_sign(uint8_t key_id,
                             const uint8_t hash[SE051_HASH_LEN],
                             uint8_t sig_out[SE051_ECDSA_MAX_DER_LEN],
                             size_t *sig_len);

se051_err_t se051_schnorr_sign(uint8_t key_id,
                               const uint8_t hash[SE051_HASH_LEN],
                               uint8_t sig_out[SE051_SCHNORR_SIG_LEN]);

se051_err_t se051_store_key(uint8_t key_id,
                            const uint8_t *key_material,
                            size_t key_len);

se051_err_t se051_delete_key(uint8_t key_id);

se051_err_t se051_get_pubkey(uint8_t key_id,
                             uint8_t pubkey_out[SE051_PUBKEY_COMPRESSED]);

se051_err_t se051_selftest(void);

se051_err_t se051_read_object(uint8_t obj_id,
                              uint8_t *buf, size_t buf_len,
                              size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif // SE051_HAL_H
