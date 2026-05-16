#ifndef PSBT_H
#define PSBT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PSBT_MAX_BUFFER   4096
#define PSBT_MAX_INPUTS   4
#define PSBT_MAX_OUTPUTS  4
#define PSBT_MAGIC_V0     0x70736274ffULL
#define PSBT_MAGIC_V2     0x70736274feULL

#define PSBT_TXID_LEN     32
#define PSBT_PUBKEY_LEN   33
#define PSBT_SIGHASH_ALL  0x01
#define PSBT_SIGHASH_NONE 0x02
#define PSBT_SIGHASH_SINGLE 0x03
#define PSBT_SIGHASH_ANYONECANPAY 0x80

#define PSBT_GLOBAL_UNSIGNED_TX   0x00
#define PSBT_GLOBAL_XPUB          0x01
#define PSBT_GLOBAL_TX_VERSION    0x02
#define PSBT_GLOBAL_VERSION       0xFB

#define PSBT_IN_NON_WITNESS_UTXO  0x00
#define PSBT_IN_WITNESS_UTXO      0x01
#define PSBT_IN_PARTIAL_SIG       0x02
#define PSBT_IN_SIGHASH_TYPE      0x03
#define PSBT_IN_REDEEM_SCRIPT     0x04
#define PSBT_IN_WITNESS_SCRIPT    0x05
#define PSBT_IN_BIP32_DERIVATION  0x06
#define PSBT_IN_PREVIOUS_TXID     0x0E
#define PSBT_IN_OUTPUT_INDEX      0x0F
#define PSBT_IN_SEQUENCE          0x10
#define PSBT_IN_TAP_KEY_SIG       0x13
#define PSBT_IN_TAP_BIP32_DERIV   0x16
#define PSBT_IN_TAP_INTERNAL_KEY  0x17

#define PSBT_OUT_REDEEM_SCRIPT    0x00
#define PSBT_OUT_WITNESS_SCRIPT   0x01
#define PSBT_OUT_BIP32_DERIVATION 0x02
#define PSBT_OUT_AMOUNT           0x03
#define PSBT_OUT_SCRIPT           0x04
#define PSBT_OUT_TAP_BIP32_DERIV  0x07

#define PSBT_PATH_MAX 6
#define PSBT_MAX_DER_SIG_LEN 72
#define PSBT_SCHNORR_SIG_LEN 64
#define PSBT_MAX_SCRIPT_LEN 128
#define PSBT_MULTISIG_MAX_KEYS 16

typedef enum {
    PSBT_OK              = 0,
    PSBT_ERR_INVALID     = 1,
    PSBT_ERR_MAGIC       = 2,
    PSBT_ERR_TOO_LARGE   = 3,
    PSBT_ERR_PARSE       = 4,
    PSBT_ERR_NO_INPUTS   = 5,
    PSBT_ERR_NO_OUTPUTS  = 6,
    PSBT_ERR_OVERFLOW    = 7,
} psbt_err_t;

typedef struct {
    bool present;
    uint8_t  fingerprint[4];
    uint32_t path[PSBT_PATH_MAX];
    uint8_t  path_len;
    uint8_t  pubkey[PSBT_PUBKEY_LEN];
} psbt_bip32_deriv_t;

typedef struct {
    bool present;
    uint64_t amount;
    uint8_t  script_pubkey[64];
    uint8_t  script_pubkey_len;
} psbt_witness_utxo_t;

typedef struct {
    uint8_t             txid[PSBT_TXID_LEN];
    uint32_t            vout;
    uint32_t            sequence;
    uint32_t            sighash_type;
    psbt_witness_utxo_t witness_utxo;
    psbt_bip32_deriv_t  bip32_derivation;
    bool                has_taproot;
    uint8_t             tap_internal_key[32];
    bool                has_partial_sig;
    uint8_t             partial_sig_pubkey[PSBT_PUBKEY_LEN];
    uint8_t             partial_sig[PSBT_MAX_DER_SIG_LEN];
    uint8_t             partial_sig_len;
    bool                has_tap_key_sig;
    uint8_t             tap_key_sig[PSBT_SCHNORR_SIG_LEN];
    bool                has_redeem_script;
    uint8_t             redeem_script[PSBT_MAX_SCRIPT_LEN];
    uint8_t             redeem_script_len;
    bool                has_witness_script;
    uint8_t             witness_script[PSBT_MAX_SCRIPT_LEN];
    uint8_t             witness_script_len;
    bool                is_multisig;
    uint8_t             multisig_m;
    uint8_t             multisig_n;
    uint8_t             multisig_existing_sigs;
} psbt_input_t;

typedef struct {
    uint64_t            amount;
    uint8_t             script_pubkey[64];
    uint8_t             script_pubkey_len;
    psbt_bip32_deriv_t  bip32_derivation;
    bool                is_change;
} psbt_output_t;

typedef struct {
    uint8_t         version;
    uint32_t        input_count;
    uint32_t        output_count;
    uint32_t        locktime;
    uint32_t        tx_version;
    bool            has_global_tx;
    bool            tx_has_segwit_marker;
    psbt_input_t    inputs[PSBT_MAX_INPUTS];
    psbt_output_t   outputs[PSBT_MAX_OUTPUTS];
} psbt_t;

psbt_err_t psbt_parse(const uint8_t *buf, size_t len, psbt_t *psbt_out);

uint64_t   psbt_get_total_input_value(const psbt_t *psbt);

uint64_t   psbt_get_total_output_value(const psbt_t *psbt);

int64_t    psbt_get_fee(const psbt_t *psbt);

size_t     psbt_serialize(const psbt_t *psbt, uint8_t *buf, size_t buf_max);

void       psbt_analyze_multisig_input(psbt_input_t *input);

const uint8_t* psbt_multisig_get_script(const psbt_input_t *input,
                                         uint8_t *script_len_out);

#ifdef __cplusplus
}
#endif

#endif
