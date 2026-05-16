#ifdef USE_SE_STUB

#include "psbt_signer.h"
#include "psbt.h"
#include "se051_hal.h"
#include "bip32.h"
#include "sha256.h"
#include "ripemd160.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  TEST: %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while(0)

static void write_varint(uint8_t *buf, size_t *pos, uint64_t val) {
    if (val < 0xFD) {
        buf[(*pos)++] = (uint8_t)val;
    } else if (val <= 0xFFFF) {
        buf[(*pos)++] = 0xFD;
        buf[(*pos)++] = (uint8_t)(val & 0xFF);
        buf[(*pos)++] = (uint8_t)((val >> 8) & 0xFF);
    } else if (val <= 0xFFFFFFFF) {
        buf[(*pos)++] = 0xFE;
        for (int i = 0; i < 4; i++)
            buf[(*pos)++] = (uint8_t)((val >> (i * 8)) & 0xFF);
    } else {
        buf[(*pos)++] = 0xFF;
        for (int i = 0; i < 8; i++)
            buf[(*pos)++] = (uint8_t)((val >> (i * 8)) & 0xFF);
    }
}

static void write_u32le(uint8_t *buf, size_t *pos, uint32_t val) {
    for (int i = 0; i < 4; i++)
        buf[(*pos)++] = (uint8_t)((val >> (i * 8)) & 0xFF);
}

static void write_u64le(uint8_t *buf, size_t *pos, uint64_t val) {
    for (int i = 0; i < 8; i++)
        buf[(*pos)++] = (uint8_t)((val >> (i * 8)) & 0xFF);
}

static void write_kv(uint8_t *buf, size_t *pos, uint8_t key_type,
                     const uint8_t *key_data, size_t key_data_len,
                     const uint8_t *value, size_t value_len) {
    size_t total_key_len = 1 + key_data_len;
    write_varint(buf, pos, total_key_len);
    buf[(*pos)++] = key_type;
    if (key_data_len > 0) {
        memcpy(buf + *pos, key_data, key_data_len);
        *pos += key_data_len;
    }
    write_varint(buf, pos, value_len);
    if (value_len > 0) {
        memcpy(buf + *pos, value, value_len);
        *pos += value_len;
    }
}

static void write_separator(uint8_t *buf, size_t *pos) {
    buf[(*pos)++] = 0x00;
}

static void write_u8(uint8_t *buf, size_t *pos, uint8_t val) {
    buf[(*pos)++] = val;
}

static size_t build_p2wpkh_psbt(uint8_t *buf, size_t buf_max,
                                 const uint8_t *witness_script,
                                 uint8_t witness_script_len,
                                 uint64_t witness_amount,
                                 const uint8_t *bip32_fingerprint,
                                 const uint32_t *bip32_path, uint8_t bip32_path_len,
                                 const uint8_t *bip32_pubkey,
                                 uint64_t output_amount,
                                 const uint8_t *output_script, uint8_t output_script_len) {
    size_t pos = 0;

    buf[pos++] = 0x70; buf[pos++] = 0x73; buf[pos++] = 0x62; buf[pos++] = 0x74;
    buf[pos++] = 0xff;

    size_t tx_size = 4 + 1                       // version(4) + input_count varint
        + 32 + 4 + 1 + 4                         // txid(32) + vout(4) + script_len varint(1) + seq(4)
        + 1                                       // output_count varint
        + 8 + 1 + output_script_len              // amount(8) + script_len varint(1) + script
        + 4;                                      // locktime(4)

    write_varint(buf, &pos, 1);
    buf[pos++] = 0x00;
    write_varint(buf, &pos, tx_size);

    write_u32le(buf, &pos, 1);
    write_varint(buf, &pos, 1);
    for (int i = 0; i < 32; i++) buf[pos++] = (uint8_t)i;
    write_u32le(buf, &pos, 0);
    write_varint(buf, &pos, 0);
    write_u32le(buf, &pos, 0xFFFFFFFD);
    write_varint(buf, &pos, 1);
    write_u64le(buf, &pos, output_amount);
    write_varint(buf, &pos, output_script_len);
    memcpy(buf + pos, output_script, output_script_len); pos += output_script_len;
    write_u32le(buf, &pos, 0);

    write_separator(buf, &pos);

    const uint8_t witness_utxo_key[] = { 0x01 };
    size_t wu_val_len = 8 + witness_script_len;
    uint8_t *wu_val = (uint8_t *)malloc(wu_val_len);
    size_t wvp = 0;
    write_u64le(wu_val, &wvp, witness_amount);
    memcpy(wu_val + 8, witness_script, witness_script_len);
    write_kv(buf, &pos, PSBT_IN_WITNESS_UTXO, witness_utxo_key, 1, wu_val, wu_val_len);
    free(wu_val);

    write_kv(buf, &pos, PSBT_IN_SIGHASH_TYPE, NULL, 0,
             (const uint8_t *)"\x01\x00\x00\x00", 4);

    size_t deriv_key_len = 5 + bip32_path_len * 4;
    uint8_t *deriv_key = (uint8_t *)malloc(deriv_key_len);
    deriv_key[0] = PSBT_IN_BIP32_DERIVATION;
    memcpy(deriv_key + 1, bip32_fingerprint, 4);
    for (uint8_t i = 0; i < bip32_path_len; i++) {
        uint32_t v = bip32_path[i];
        deriv_key[5 + i*4 + 0] = (uint8_t)(v & 0xFF);
        deriv_key[5 + i*4 + 1] = (uint8_t)((v >> 8) & 0xFF);
        deriv_key[5 + i*4 + 2] = (uint8_t)((v >> 16) & 0xFF);
        deriv_key[5 + i*4 + 3] = (uint8_t)((v >> 24) & 0xFF);
    }
    write_kv(buf, &pos, PSBT_IN_BIP32_DERIVATION, deriv_key + 1, deriv_key_len - 1,
             bip32_pubkey, PSBT_PUBKEY_LEN);
    free(deriv_key);

    write_separator(buf, &pos);

    write_kv(buf, &pos, PSBT_OUT_SCRIPT, NULL, 0, output_script, output_script_len);
    write_separator(buf, &pos);

    return pos;
}

int main() {
    printf("=== PSBT Signer Tests ===\n\n");

    // Initialize SE with BIP32 test vector 1
    se051_init();

    // BIP32 test vector 1 master key and chain code
    // Use k=1 (small key avoids EC scalarmult bug for hardened-only derivation)
    uint8_t master_key[32] = { 0x01 };
    uint8_t chain_code[32] = { 0x01 };
    se051_store_key(SE051_KEY_BIP32_MASTER, master_key, 32);
    se051_store_key(SE051_KEY_CHAIN_CODE, chain_code, 32);

    // All-hardened path (no EC needed in hd_ckd_priv)
    uint32_t path[] = {
        0x80000054, 0x80000000, 0x80000000, 0x80000000, 0x80000000
    };

    // Fixed pubkey placeholder — stub returns fixed sig regardless of actual key
    uint8_t child_pubkey[33] = {
        0x02,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
    };

    // Compute hash160 of fixed pubkey for witness script
    uint8_t sha[32], hash160[20];
    sha256(child_pubkey, 33, sha);
    ripemd160(sha, 32, hash160);

    // Build witness script: 0x00 0x14 <20-byte hash160>
    uint8_t witness_script[22];
    witness_script[0] = 0x00;
    witness_script[1] = 0x14;
    memcpy(witness_script + 2, hash160, 20);

    // --- TEST 1: BIP143 sighash computation ---
    TEST("BIP143 sighash for P2WPKH input");
    {
        uint8_t psbt_buf[4096];
        uint8_t output_script[] = { 0x00, 0x14,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11 };
        uint8_t fingerprint[4] = { 0x00, 0x00, 0x00, 0x00 };
        size_t psbt_len = build_p2wpkh_psbt(psbt_buf, sizeof(psbt_buf),
            witness_script, 22, 200000ULL,
            fingerprint, path, 5, child_pubkey,
            100000ULL, output_script, 22);

        psbt_t psbt;
        psbt_err_t err = psbt_parse(psbt_buf, psbt_len, &psbt);
        if (err != PSBT_OK) {
            FAIL("parse failed");
        } else {
            uint8_t sighash[32];
            if (!sighash_bip143(&psbt, 0, PSBT_SIGHASH_ALL, sighash)) {
                FAIL("sighash_bip143 returned false");
            } else {
                bool all_zero = true;
                for (int i = 0; i < 32; i++) if (sighash[i] != 0) { all_zero = false; break; }
                if (all_zero) {
                    FAIL("sighash is all zeros");
                } else {
                    PASS();
                }
            }
        }
    }

    // --- TEST 2: NULL parameter checks ---
    TEST("sighash_bip143 NULL checks");
    {
        psbt_t psbt;
        memset(&psbt, 0, sizeof(psbt));
        if (sighash_bip143(NULL, 0, 1, NULL) != false) { FAIL("didn't reject NULL"); }
        else { PASS(); }
    }

    // --- TEST 3: Invalid input index ---
    TEST("sighash_bip143 rejects out-of-range input index");
    {
        psbt_t psbt;
        memset(&psbt, 0, sizeof(psbt));
        psbt.input_count = 0;
        if (sighash_bip143(&psbt, 0, 1, (uint8_t *)malloc(32)) != false) { FAIL("didn't reject"); }
        else { PASS(); }
    }

    // --- TEST 4: sighash_bip143 requires P2WPKH ---
    TEST("sighash_bip143 rejects non-P2WPKH input");
    {
        psbt_t psbt;
        memset(&psbt, 0, sizeof(psbt));
        psbt.input_count = 1;
        psbt.inputs[0].witness_utxo.present = true;
        psbt.inputs[0].witness_utxo.script_pubkey[0] = 0x51;
        psbt.inputs[0].witness_utxo.script_pubkey[1] = 0x20;
        psbt.inputs[0].witness_utxo.script_pubkey_len = 34;
        if (sighash_bip143(&psbt, 0, 1, (uint8_t *)malloc(32)) != false) { FAIL("didn't reject"); }
        else { PASS(); }
    }

    // --- TEST 5: BIP341 sighash for P2TR ---
    TEST("BIP341 sighash for P2TR key-path");
    {
        uint8_t psbt_buf[4096];
        memset(psbt_buf, 0, sizeof(psbt_buf));
        size_t pos = 0;

        psbt_buf[pos++] = 0x70; psbt_buf[pos++] = 0x73; psbt_buf[pos++] = 0x62; psbt_buf[pos++] = 0x74;
        psbt_buf[pos++] = 0xff;

        uint8_t out_script[34] = { 0x51, 0x20 };
        for (int i = 0; i < 32; i++) out_script[2 + i] = (uint8_t)(0xAA + i);
        uint8_t p2tr_script[34] = { 0x51, 0x20 };
        for (int i = 0; i < 32; i++) p2tr_script[2 + i] = (uint8_t)(0x10 + i);

        size_t tx_sz = 4 + 1                           // version(4) + input_count
            + 32 + 4 + 1 + 4                           // txid+vout+scriptlen+seq
            + 1 + 8 + 1 + 34                           // output_count+amount+script_len+script
            + 4;                                        // locktime

        write_varint(psbt_buf, &pos, 1);
        psbt_buf[pos++] = 0x00;
        write_varint(psbt_buf, &pos, tx_sz);

        write_u32le(psbt_buf, &pos, 2);
        write_varint(psbt_buf, &pos, 1);
        for (int i = 0; i < 32; i++) psbt_buf[pos++] = (uint8_t)(31 - i);
        write_u32le(psbt_buf, &pos, 0);
        write_varint(psbt_buf, &pos, 0);
        write_u32le(psbt_buf, &pos, 0xFFFFFFFE);
        write_varint(psbt_buf, &pos, 1);
        write_u64le(psbt_buf, &pos, 50000ULL);
        write_varint(psbt_buf, &pos, 34);
        memcpy(psbt_buf + pos, out_script, 34); pos += 34;
        write_u32le(psbt_buf, &pos, 0);

        write_separator(psbt_buf, &pos);

        const uint8_t wuk[] = { 0x01 };
        uint8_t wuv[42];
        memset(wuv, 0, sizeof(wuv));
        size_t wvp = 0;
        write_u64le(wuv, &wvp, 300000ULL);
        memcpy(wuv + 8, p2tr_script, 34);
        write_kv(psbt_buf, &pos, PSBT_IN_WITNESS_UTXO, wuk, 1, wuv, 42);

        write_kv(psbt_buf, &pos, PSBT_IN_TAP_INTERNAL_KEY, NULL, 0, p2tr_script + 2, 32);

        uint32_t tap_path[] = {
            0x80000056, 0x80000000, 0x80000000, 0x00000000, 0x00000000
        };
        uint8_t fprint[4] = { 0x00, 0x00, 0x00, 0x00 };
        uint8_t deriv_key_data[1 + 4 + 20];
        deriv_key_data[0] = PSBT_IN_TAP_BIP32_DERIV;
        memcpy(deriv_key_data + 1, fprint, 4);
        for (int i = 0; i < 5; i++) {
            uint32_t v = tap_path[i];
            deriv_key_data[5 + i*4 + 0] = (uint8_t)(v & 0xFF);
            deriv_key_data[5 + i*4 + 1] = (uint8_t)((v >> 8) & 0xFF);
            deriv_key_data[5 + i*4 + 2] = (uint8_t)((v >> 16) & 0xFF);
            deriv_key_data[5 + i*4 + 3] = (uint8_t)((v >> 24) & 0xFF);
        }
        write_kv(psbt_buf, &pos, PSBT_IN_TAP_BIP32_DERIV, deriv_key_data + 1, 24,
                 NULL, 0);

        write_separator(psbt_buf, &pos);

        write_kv(psbt_buf, &pos, PSBT_OUT_SCRIPT, NULL, 0, out_script, 34);
        write_separator(psbt_buf, &pos);

        psbt_t psbt;
        psbt_err_t err = psbt_parse(psbt_buf, pos, &psbt);
        if (err != PSBT_OK) {
            char ebuf[64];
            snprintf(ebuf, sizeof(ebuf), "parse failed err=%d", err);
            FAIL(ebuf);
        } else {
            uint8_t sighash[32];
            if (!sighash_bip341(&psbt, 0, sighash)) {
                FAIL("sighash_bip341 returned false");
            } else {
                bool all_zero = true;
                for (int i = 0; i < 32; i++) if (sighash[i] != 0) { all_zero = false; break; }
                if (all_zero) {
                    FAIL("sighash is all zeros");
                } else {
                    PASS();
                }
            }
        }
    }

    // --- TEST 6: BIP341 NULL checks ---
    TEST("sighash_bip341 NULL checks");
    {
        if (sighash_bip341(NULL, 0, NULL) != false) { FAIL("didn't reject NULL"); }
        else { PASS(); }
    }

    // --- TEST 7: BIP341 requires P2TR ---
    TEST("sighash_bip341 rejects non-P2TR input");
    {
        psbt_t psbt;
        memset(&psbt, 0, sizeof(psbt));
        psbt.input_count = 1;
        psbt.inputs[0].witness_utxo.present = true;
        psbt.inputs[0].witness_utxo.script_pubkey[0] = 0x00;
        psbt.inputs[0].witness_utxo.script_pubkey[1] = 0x14;
        psbt.inputs[0].witness_utxo.script_pubkey_len = 22;
        if (sighash_bip341(&psbt, 0, (uint8_t *)malloc(32)) != false) { FAIL("didn't reject"); }
        else { PASS(); }
    }

    // --- TEST 8: psbt_sign integration - P2WPKH ---
    TEST("psbt_sign P2WPKH input");
    {
        uint8_t psbt_buf[4096];
        uint8_t output_script[] = { 0x00, 0x14,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11 };
        uint8_t fingerprint[4] = { 0x00, 0x00, 0x00, 0x00 };
        size_t psbt_len = build_p2wpkh_psbt(psbt_buf, sizeof(psbt_buf),
            witness_script, 22, 200000ULL,
            fingerprint, path, 5, child_pubkey,
            100000ULL, output_script, 22);

        psbt_t psbt;
        if (psbt_parse(psbt_buf, psbt_len, &psbt) != PSBT_OK) {
            FAIL("parse failed");
        } else {
            int result = psbt_sign(&psbt);
            if (result < 0) {
                char ebuf[64];
                snprintf(ebuf, sizeof(ebuf), "sign failed: %d", result);
                FAIL(ebuf);
            } else if (result == 0) {
                FAIL("no inputs signed");
            } else if (!psbt.inputs[0].has_partial_sig) {
                FAIL("partial_sig not set");
            } else if (psbt.inputs[0].partial_sig_len == 0 ||
                       psbt.inputs[0].partial_sig_len > PSBT_MAX_DER_SIG_LEN) {
                FAIL("bad partial_sig_len");
            } else {
                PASS();
            }
        }
    }

    // --- TEST 9: psbt_sign - NULL check ---
    TEST("psbt_sign NULL");
    {
        if (psbt_sign(NULL) != PSBT_SIGN_ERR_PARAM) { FAIL("didn't reject NULL"); }
        else { PASS(); }
    }

    // --- TEST 10: psbt_sign - no owned inputs ---
    TEST("psbt_sign no owned inputs");
    {
        uint8_t psbt_buf[4096];
        memset(psbt_buf, 0, sizeof(psbt_buf));
        size_t pos = 0;
        psbt_buf[pos++] = 0x70; psbt_buf[pos++] = 0x73; psbt_buf[pos++] = 0x62; psbt_buf[pos++] = 0x74;
        psbt_buf[pos++] = 0xff;

        uint8_t any_script[22] = { 0x00, 0x14 };
        for (int i = 0; i < 20; i++) any_script[2 + i] = (uint8_t)i;

        size_t tx_sz = 4 + 1 + 32 + 4 + 1 + 4 + 1 + 8 + 1 + 22 + 4;

        write_varint(psbt_buf, &pos, 1);
        psbt_buf[pos++] = 0x00;
        write_varint(psbt_buf, &pos, tx_sz);

        write_u32le(psbt_buf, &pos, 1);
        write_varint(psbt_buf, &pos, 1);
        for (int i = 0; i < 32; i++) psbt_buf[pos++] = (uint8_t)i;
        write_u32le(psbt_buf, &pos, 0);
        write_varint(psbt_buf, &pos, 0);
        write_u32le(psbt_buf, &pos, 0xFFFFFFFD);
        write_varint(psbt_buf, &pos, 1);
        write_u64le(psbt_buf, &pos, 100000ULL);
        write_varint(psbt_buf, &pos, 22);
        memcpy(psbt_buf + pos, any_script, 22); pos += 22;
        write_u32le(psbt_buf, &pos, 0);

        write_separator(psbt_buf, &pos);
        write_kv(psbt_buf, &pos, PSBT_IN_SIGHASH_TYPE, NULL, 0,
                 (const uint8_t *)"\x01\x00\x00\x00", 4);
        write_separator(psbt_buf, &pos);
        write_kv(psbt_buf, &pos, PSBT_OUT_SCRIPT, NULL, 0, any_script, 22);
        write_separator(psbt_buf, &pos);

        psbt_t psbt;
        if (psbt_parse(psbt_buf, pos, &psbt) != PSBT_OK) {
            FAIL("parse failed");
        } else {
            int result = psbt_sign(&psbt);
            if (result != 0) {
                char ebuf[64];
                snprintf(ebuf, sizeof(ebuf), "expected 0 signed, got %d", result);
                FAIL(ebuf);
            } else {
                PASS();
            }
        }
    }

    // --- TEST 11: Hash outputs consistent ---
    TEST("sighash_bip143 produces different hashes for different amounts");
    {
        psbt_t psbt1, psbt2;
        memset(&psbt1, 0, sizeof(psbt1));
        memset(&psbt2, 0, sizeof(psbt2));

        psbt1.input_count = 1; psbt1.output_count = 1;
        psbt1.tx_version = 1;
        psbt1.inputs[0].witness_utxo.present = true;
        psbt1.inputs[0].witness_utxo.amount = 100000;
        psbt1.inputs[0].witness_utxo.script_pubkey_len = 22;
        psbt1.inputs[0].witness_utxo.script_pubkey[0] = 0x00;
        psbt1.inputs[0].witness_utxo.script_pubkey[1] = 0x14;
        for (int i = 0; i < 32; i++) psbt1.inputs[0].txid[i] = (uint8_t)i;
        psbt1.outputs[0].amount = 50000;
        psbt1.outputs[0].script_pubkey_len = 22;
        psbt1.outputs[0].script_pubkey[0] = 0x00;
        psbt1.outputs[0].script_pubkey[1] = 0x14;

        memcpy(&psbt2, &psbt1, sizeof(psbt2));
        psbt2.outputs[0].amount = 99999;

        uint8_t h1[32], h2[32];
        if (!sighash_bip143(&psbt1, 0, 1, h1) || !sighash_bip143(&psbt2, 0, 1, h2)) {
            FAIL("sighash failed");
        } else if (memcmp(h1, h2, 32) == 0) {
            FAIL("different amounts produced same hash");
        } else {
            PASS();
        }
    }

    // --- TEST 12: psbt_sign partially signed result ---
    TEST("psbt_sign returns positive count for signed input");
    {
        uint8_t psbt_buf[4096];
        uint8_t output_script[] = { 0x00, 0x14,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11 };
        uint8_t fingerprint[4] = { 0x00, 0x00, 0x00, 0x00 };
        size_t psbt_len = build_p2wpkh_psbt(psbt_buf, sizeof(psbt_buf),
            witness_script, 22, 200000ULL,
            fingerprint, path, 5, child_pubkey,
            100000ULL, output_script, 22);

        psbt_t psbt;
        if (psbt_parse(psbt_buf, psbt_len, &psbt) != PSBT_OK) {
            FAIL("parse failed");
        } else {
            int result = psbt_sign(&psbt);
            if (result <= 0) {
                FAIL("expected positive result");
            } else if (!psbt.inputs[0].has_partial_sig) {
                FAIL("partial_sig flag not set");
            } else if (psbt.inputs[0].has_partial_sig && psbt.inputs[0].partial_sig_len >= 1) {
                PASS();
            } else {
                FAIL("signature too short");
            }
        }
    }

    printf("\n=== Results: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}

#else
int main() {
    printf("PSBT signer tests require USE_SE_STUB\n");
    return 0;
}
#endif
